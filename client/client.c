#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>

#include "../server/coding.h"
#include "net_message.h"

struct work {
    int start;
    int end;
};

typedef struct messages {
    int len;
    char* buffer;
} messages_t;

int g_thread_num;
int g_policy_num;
net_person_policy_t* Policy = NULL;
messages_t* Messages = NULL;

int socket_init(char* server, int port) {
    int connfd;
    struct sockaddr_in servaddr;

    connfd = socket(AF_INET, SOCK_STREAM, 0);
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(port);
    inet_pton(AF_INET, server, &servaddr.sin_addr);

    if (connect(connfd, (struct sockaddr*) &servaddr, sizeof(servaddr)) < 0) {
        return -1;
    }

    return connfd;
}

int role_init(int *role, int *num) {

    *num = 40;

    role[0] = 1;    role[1] = 6;    role[2] = 8;    role[3] = 9;
    role[4] = 12;   role[5] = 13;   role[6] = 14;   role[7] = 15;
    role[8] = 16;   role[9] = 17;   role[10] = 18;  role[11] = 22;
    role[12] = 23;  role[13] = 24;  role[14] = 25;  role[15] = 26;
    role[16] = 27;  role[17] = 28;  role[18] = 29;  role[19] = 30;
    role[20] = 31;  role[21] = 33;  role[22] = 35;  role[23] = 42;
    role[24] = 43;  role[25] = 44;  role[26] = 45;  role[27] = 46;
    role[28] = 47;  role[29] = 49;  role[30] = 50;  role[31] = 51;
    role[32] = 52;  role[33] = 54;  role[34] = 55;  role[35] = 56;
    role[36] = 57;  role[37] = 58;  role[38] = 61;  role[39] = 62;

    return 0;
}

int policy_init() {
    int i, j;
    int role[40], num;

    role_init(role, &num);

    Policy = (net_person_policy_t*)malloc(sizeof(net_person_policy_t) * g_policy_num);

    if (Policy == NULL) {
        return -1;
    }

    memset(Policy, 0, sizeof(net_person_policy_t)*g_policy_num);

    for (i = 0; i < g_policy_num; i++) {
        Policy[i].option = htonl(NET_OPTION_ADD);
        Policy[i].user_ip = htonl(0xC0A80002 + i);
        Policy[i].role_id = htonl(role[i%num]);
        sprintf(Policy[i].user_name, "Test_%d", i);
    }

    return 0;
}

int message_init() {
    int i, j;

    Messages = (messages_t*)malloc(sizeof(messages_t) * g_policy_num);

    if (Messages == NULL) {
        return -1;
    }

    for (i = 0; i < g_policy_num; i++) {
        char* buffer;
        int buffer_len;
        net_request_head_t* pHead = (net_request_head_t*)malloc(REQUEST_MESSAGE_LEN(net_person_policy_t,
                                    1));
        net_person_policy_t* policy = (net_person_policy_t*)(pHead + 1);

        memcpy(pHead->key, " :-) ", sizeof(pHead->key));
        pHead->msgtype = htonl(NET_MESSAGE_UPDATE_PERSON_POLICY);
        pHead->bodylen = htonl(sizeof(net_person_policy_t));
        memcpy(policy, Policy + i, sizeof(net_person_policy_t));
        encoding((char*)pHead, REQUEST_MESSAGE_LEN(net_person_policy_t, 1), &buffer, &buffer_len);

        Messages[i].buffer = buffer;
        Messages[i].len = buffer_len;
    }

    return 0;
}

void* PushRules(void* arg) {
    int i;
    struct work* w = (struct work*)arg;
    char pRHead[1024];

    for (i = w->start; i < w->end; i++) {
        int sock;
        int len, buffer_len;
        char* buffer;

        buffer = Messages[i].buffer;
        buffer_len = Messages[i].len;

        if ((sock = socket_init("127.0.0.1", PORT)) < 0) {
            printf("socket init failed ret %d errno %d\n", sock, errno);
            exit(1);
        }

        len = write(sock, buffer, buffer_len);

        if (len != buffer_len) {
            printf("send rules failed(index %d ), len %d ret %d errno %d\n", i, buffer_len, len, errno);
            exit(1);
        }

        len = read(sock, &buffer_len, 4);
        len = read(sock, pRHead, ntohl(buffer_len));

        if (len != ntohl(buffer_len)) {
            printf("read response error ret %d errno %d\n", len, errno);
            exit(1);
        }

        close(sock);
    }

    return NULL;;
}

int main(int argc, char** argv) {
    struct timeval start, end;
    uint32_t time;
    int i;

    if (argc != 3) {
        printf("Usage: ./client thread_num policy_num\n");
        exit(1);
    }

    g_thread_num = atoi(argv[1]);
    g_policy_num = atoi(argv[2]);

    if (policy_init() < 0) {
        printf("policy init failed\n");
        exit(1);
    }

    init_coding();
    message_init();

    if (g_thread_num > 0) {
        pthread_t* tid = (pthread_t*)malloc(sizeof(pthread_t) * g_thread_num);
        struct work* w = (struct work*)malloc(sizeof(struct work) * g_thread_num);

        gettimeofday(&start, NULL);

        for (i = 0; i < g_thread_num; i++) {
            w[i].start = i * (g_policy_num / g_thread_num);
            w[i].end = (i + 1) * (g_policy_num / g_thread_num);
            w[i].end = w[i].end > g_policy_num ? g_policy_num : w[i].end;
            pthread_create(tid + i, NULL, PushRules, w + i);
        }

        for (i = 0; i < g_thread_num; i++) {
            pthread_join(tid[i], NULL);
        }

        gettimeofday(&end, NULL);
    } else {
        struct work w;
        gettimeofday(&start, NULL);
        w.start = 0;
        w.end = g_policy_num;
        PushRules(&w);
        gettimeofday(&end, NULL);
    }

    time = 1000000 * (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec);
    printf("policy num %d, time %fms\n", g_policy_num, time / 1000.0);

    return 0;
}
