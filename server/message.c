#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/epoll.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <syslog.h>

#include "lock.h"
#include "event.h"
#include "coding.h"
#include "message.h"

static struct Connection_list conn_list1 = STAILQ_HEAD_INITIALIZER(conn_list1);
static struct Connection_list conn_list2 = STAILQ_HEAD_INITIALIZER(conn_list2);
static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
static int kernel_sock;

/* mutex lock for connection thread and message thread */
pthread_mutex_t Thread_mutex_lock = PTHREAD_MUTEX_INITIALIZER;

/* pre alloc buffer for response msg used by message handle modules
 * and data size of _rsp is no less than RESPONSE_MESSAGE_LEN(net_option_result_t, 1)
 * */
struct Buffer _rsp;

/* caller could used this buffer, but do not free it! */
char* get_pre_response_buffer(int len) {
    if (alloc_buffer_data(&_rsp, len) == 0) {
        return _rsp.data;
    }

    return NULL;
}

int message_set_to_kernel(int msg_type, void* msg, int msglen) {
    return setsockopt(kernel_sock, IPPROTO_IP, msg_type, msg, msglen);
}

int message_get_from_kernel(int msg_type, void* buf, int* buflen) {
    return getsockopt(kernel_sock, IPPROTO_IP, msg_type, buf, (socklen_t*)buflen);
}

int process_message(char* request, int rlen, char** response, int* slen) {
    int ret = -1;
    net_request_head_t* req = (net_request_head_t*)request;

    req->msgtype = ntohl(req->msgtype);
    req->bodylen = ntohl(req->bodylen);

    switch (req->msgtype) {
    case NET_MESSAGE_UPDATE_WHITE_RULE:
    case NET_MESSAGE_RELOAD_WHITE_RULE:
    case NET_MESSAGE_QUE_WHITE_RULE:
        //ret = handle_whiteRule_message(request, rlen, response, slen);
        break;

    case NET_MESSAGE_UPDATE_PERSON_ACL:
    case NET_MESSAGE_QUE_PERSON_ACL:
        //ret = handle_personAcl_message(request, rlen, response, slen);
        break;

    case NET_MESSAGE_UPDATE_PERSON_POLICY:
    case NET_MESSAGE_QUE_PERSON_POLICY:
        ret = handle_personPolicy_message(request, rlen, response, slen);
        break;

    case NET_MESSAGE_UPDATE_ROLE_POLICY:
    case NET_MESSAGE_RELOAD_ROLE_POLICY:
    case NET_MESSAGE_QUE_ROLE_POLICY:
        //ret = handle_rolePolicy_message(request, rlen, response, slen);
        break;

    case NET_MESSAGE_DEFAULT_PERMIT:
    case NET_MESSAGE_DEFAULT_DROP:
    case NET_MESSAGE_QUE_DEFAULT:
        //ret = handle_configure_message(request, rlen, response, slen);
        break;

    default:
        message_log(LOG_ERR, 0,
                        "process message failed, invalid type %u", req->msgtype);
    }

    if (*response) {
        net_response_head_t* rsp = (net_response_head_t*)(*response);
        memcpy(rsp->key, req->key, sizeof(rsp->key));
        rsp->msgtype = htonl(req->msgtype);
        rsp->msgresult = htonl(rsp->msgresult);
        rsp->bodylen = htonl(rsp->bodylen);
    }

#ifdef DEBUG_DUMP
    /* recover net data to dump message */
    req->msgtype = htonl(req->msgtype);
    req->bodylen = htonl(req->bodylen);
#endif

    return ret;
}

static int handle_net_message(struct Connection* conn) {
    int remote;
    int rcvlen, sndlen;
    char* rcvbuffer, *sndbuffer;
    struct Buffer* in = &(conn->in_buffer);
    struct Buffer* out = &(conn->out_buffer);

    rcvlen = sndlen = 0;
    rcvbuffer = sndbuffer = NULL;
    remote = conn->remote;

    if (decoding(in->data, in->len, &rcvbuffer, &rcvlen) < 0) {
        goto error_process;
    }

    if (rcvlen < (int)sizeof(net_request_head_t)) {
        message_log(LOG_ERR, 0,
                        "process %x's message failed: size %d", remote, rcvlen);
        goto error_process;
    }

    message_head_log(rcvbuffer, remote);

    if (process_message(rcvbuffer, rcvlen, &sndbuffer, &sndlen) != 0) {
        goto error_process;
    }

#ifdef DEBUG_DUMP
    dump_request(rcvbuffer, remote);
#endif

error_process:

    /* In some failure cases, sndbuffer may be NULL
     * here try our best to send a message to remote which contains the lastest log message */
    if (sndbuffer == NULL) {
        net_response_head_t* rsp;
        net_option_result_t* result;

        sndlen = RESPONSE_MESSAGE_LEN(net_option_result_t, 1);
        sndbuffer = get_pre_response_buffer(sndlen);
        memset(sndbuffer, 0, sndlen);

        rsp = (net_response_head_t*)(sndbuffer);
        result = (net_option_result_t*)(rsp + 1);
        rsp->msgtype = htonl(NET_MESSAGE_MAX);
        memcpy(rsp->key, "> - < !!", sizeof(rsp->key));
        rsp->msgresult = htonl(NET_INTERNAL_ERR);
        rsp->bodylen = htonl(sizeof(net_option_result_t));
        strncpy(result->reason, get_message_log(), sizeof(result->reason) - 1);
    }

#ifdef DEBUG_DUMP
    dump_response(sndbuffer, remote);
#endif

    if (encoding(sndbuffer, sndlen, &(out->data), &(out->len)) < 0) {
        syslog(LOG_ERR, "encoding payload failed\n");
        destroy_connection(conn);
        return -1;
    }

    if (Event.add_connection(conn, CONNECTION_ACTIVE_WRITE) < 0) {
        syslog(LOG_ERR, "change connection writeable failed\n");
        destroy_connection(conn);
        return -1;
    }

    return 0;
}

static void* pthread_handle_connection(void* para) {
    struct Connection* tmp;
    struct Connection* entry;
    int count = 0;

    while (1) {
        thread_mutex_lock();
        STAILQ_SWAP(&conn_list1, &conn_list2, Connection);
        thread_mutex_unlock();

        count = 0;
        STAILQ_FOREACH_SAFE(entry, &conn_list2, next, tmp) {
            STAILQ_REMOVE(&conn_list2, entry, Connection, next);
            handle_net_message(entry);
            count++;
        }

        /* if no work to do, then go to sleep :-) */
        if (count == 0) {
            thread_mutex_lock();
            pthread_cond_wait(&cond, &Thread_mutex_lock);
            thread_mutex_unlock();
        }

#if _BullseyeCoverage
        cov_write();
#endif
    }

    return NULL;
}

static int create_messageThread() {
    pthread_attr_t attr;
    pthread_t threadId;

    pthread_attr_init(&attr);
    pthread_attr_setscope(&attr, PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    if (pthread_create(&threadId, &attr, pthread_handle_connection, NULL)) {
        return -1;
    }

    return 0;
}

void wakeup_message_thread() {
    int empty = 0;

    thread_mutex_lock();
    empty = STAILQ_EMPTY(&conn_list1);
    thread_mutex_unlock();

    if (!empty) {
        /* wake up work thread */
        pthread_cond_signal(&cond);
    }
}

int deliver_message(struct Connection* conn) {
    thread_mutex_lock();
    STAILQ_INSERT_TAIL(&conn_list1, conn, next);
    thread_mutex_unlock();

    return 0;
}

int init_message() {
    /* pre alloc _rsp buffer */
    init_buffer(&_rsp);

    if (get_pre_response_buffer(RESPONSE_MESSAGE_LEN(net_option_result_t, 1)) == NULL) {
        syslog(LOG_ERR, "pre alloc response buffer failed.");
        exit(EXIT_FAILURE);
    }

    kernel_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    if (kernel_sock < 0) {
        syslog(LOG_ERR, "open kernel socket failed.");
        exit(EXIT_FAILURE);
    }

    if (create_messageThread() < 0) {
        syslog(LOG_ERR, "init message thread failed.");
        exit(EXIT_FAILURE);
    }

    syslog(LOG_INFO, "init message ok.");
    return 0;
}

static char config_path[64] = "/home/whiteRule_rolePolicy.sh";

int init_path(char* path) {
    int fd;
    struct stat statbuf;

    if (path != NULL) {
        if (strlen(path) > (sizeof(config_path) - 1)) {
            syslog(LOG_ERR, "init message thread failed.");
            exit(EXIT_FAILURE);
        }

        strcpy(config_path, path);
    }

    if (0 != stat(config_path, &statbuf)) {
        if (ENOENT == errno) {
            /* if file didn't exist, create it */
            if ((fd = open(config_path,
                           O_WRONLY | O_CREAT | O_TRUNC, S_IRWXU | S_IRGRP | S_IROTH)) < 0) {
                syslog(LOG_ERR, "creat file %s error %d.", config_path, errno);
                exit(EXIT_FAILURE);
            }

            close(fd);
        }
    }

    syslog(LOG_INFO, "init config path %s ok.", config_path);
    return 0;
}
