#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <unistd.h>

#include "event.h"
#include "message.h"
#include "connection.h"

int read_event(struct Connection* conn);
int write_event(struct Connection* conn);

static int setnonblocking(int sockfd) {
    if (fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFD, 0) | O_NONBLOCK) == -1) {
        return -1;
    }

    return 0;
}

struct Connection* alloc_remote_connection(int accept, int remote) {
    struct Connection* conn = (struct Connection*)calloc(1, sizeof(struct Connection));

    if (conn) {
        conn->fd = accept;
        conn->remote = remote;
        conn->read_process = read_event;
        conn->write_process = write_event;
        connection_log(LOG_INFO, remote,
                           "connection(%p) alloc success", conn);
    }

    return conn;
}

void destroy_connection(struct Connection* conn) {
    struct Buffer* buf = NULL;

    connection_log(LOG_INFO, conn->remote,
                       "connection(%p) destroy", conn);

    buf = &(conn->in_buffer);
    free_buffer_data(buf);

    buf = &(conn->out_buffer);
    free_buffer_data(buf);

    close(conn->fd);
    free(conn);
}

int read_event(struct Connection* conn) {
    int rlen, ret, offset;
    struct Buffer* buf = &(conn->in_buffer);
    char* rcv;

    if (buf->data == NULL) {
        int len;

        ret = read(conn->fd, &len, sizeof(int));

        if (ret == 0 && errno == EAGAIN) {
            return 0;
        } else if (ret != sizeof(int)) {
            connection_log(LOG_ERR, conn->remote,
                               "connection(%p) read len error ret %d errno %d", conn, ret, errno);
            goto error;
        }

        rlen = ntohl(len);

        if (rlen <= 0) {
            connection_log(LOG_ERR, conn->remote,
                               "connection(%p) payload len error %d", conn, rlen);
            goto error;
        }

        if (alloc_buffer_data(buf, rlen) < 0) {
            connection_log(LOG_ERR, conn->remote,
                               "connection(%p) alloc payload data failed", conn);
            goto error;
        }
    }

    rlen = buf->len;
    offset = buf->offset;
    rcv = buf->data;

    while ((ret = read(conn->fd, rcv + offset, rlen - offset)) > 0) {
        offset += ret;
    }

    if (ret == -1 && errno != EAGAIN) {
        connection_log(LOG_ERR, conn->remote,
                           "connection(%p) read buffer failed", conn);
        goto error;
    }

    buf->offset = offset;

    if (offset == rlen) {
        if (Event.delete_connection(conn) != 0) {
            connection_log(LOG_ERR, conn->remote,
                               "connection(%p) delete failed errno %d", conn, errno);
            destroy_connection(conn);
            return -1;
        }

        deliver_message(conn);
    }

    return 0;

error:
    Event.delete_connection(conn);
    destroy_connection(conn);
    return -1;
}

int write_event(struct Connection* conn) {
    int slen, ret, offset;
    struct Buffer* buf;
    char* send;

    buf = &(conn->out_buffer);

    if (buf->data == NULL) {
        connection_log(LOG_ERR, conn->remote,
                           "connection(%p) out data is NULL", conn);
        Event.delete_connection(conn);
        destroy_connection(conn);
        return -1;
    }

    slen = buf->len;
    offset = buf->offset;
    send = buf->data;

    while (offset < slen) {
        ret = write(conn->fd, send + offset, slen - offset);

        if (ret < (slen - offset)) {
            if (ret == -1 && errno != EAGAIN) {
                connection_log(LOG_ERR, conn->remote,
                                   "connection(%p) response failed ret %d errno %d: total %d, snd %d", conn, ret, errno, slen, offset);
                Event.delete_connection(conn);
                destroy_connection(conn);
                return -2;
            }

            offset += ret;
            break;
        }

        offset += ret;
    }

    buf->offset = offset;

    if (offset == slen) {
        Event.delete_connection(conn);
        destroy_connection(conn);
    }

    return 0;
}

int accept_event(struct Connection* conn) {
    int accepter;
    struct sockaddr_in their_addr;
    socklen_t len = sizeof(struct sockaddr_in);

    while ((accepter = accept(conn->fd, (struct sockaddr*)&their_addr, &len)) > 0) {
        int remote = *(int*)&their_addr.sin_addr;
        struct Connection* new_conn = alloc_remote_connection(accepter, remote);

        if (NULL == new_conn) {
            connection_log(LOG_ERR, remote,
                               "connection alloc failed");
            close(accepter);
            continue;
        }

        if (setnonblocking(accepter) < 0) {
            connection_log(LOG_ERR, remote,
                               "connection(%p) set nonblock failed errno %d", new_conn, errno);
            destroy_connection(new_conn);
            continue;
        }

        if (Event.add_connection(new_conn, CONNECTION_ACTIVE_READ) != 0) {
            connection_log(LOG_ERR, remote,
                               "connection(%p) add read event failed errno %d", new_conn, errno);
            destroy_connection(new_conn);
        }
    }

    if (accepter < 0) {
        if (errno != EAGAIN && errno != ECONNABORTED && errno != EPROTO && errno != EINTR) {
            syslog(LOG_ERR, "accept error");
        }
    }

    return 0;
}

int tcp_bind_listener(uint16_t port) {
    struct sockaddr_in my_addr;
    int listener;
    int opt = SO_REUSEADDR;
    struct Connection* listener_conn = NULL;

    listener_conn = (struct Connection*)calloc(1, sizeof(struct Connection));

    if (NULL == listener_conn) {
        return -1;
    }

    if ((listener = socket(PF_INET, SOCK_STREAM, 0)) == -1) {
        return -2;
    }

    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    if (setnonblocking(listener) < 0) {
        return -3;
    }

    bzero(&my_addr, sizeof(my_addr));
    my_addr.sin_family = PF_INET;
    my_addr.sin_port = htons(port);
    my_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(listener, (struct sockaddr*)&my_addr, sizeof(struct sockaddr)) == -1) {
        return -4;
    }

    if (listen(listener, MAX_CONNECTIONS) == -1) {
        return -5;
    }

    listener_conn->fd = listener;
    listener_conn->expire = -1;
    listener_conn->read_process = accept_event;
    listener_conn->write_process = write_event;

    if (Event.add_connection(listener_conn, CONNECTION_ACTIVE_READ) != 0) {
        return -6;
    }

    return 0;
}

int init_connection() {
    int ret;

    if ((ret = tcp_bind_listener(LISTENER_PORT)) < 0) {
        syslog(LOG_ERR, "bind port %d failed ret %d.", LISTENER_PORT, ret);
        exit(EXIT_FAILURE);
    }

    syslog(LOG_INFO, "init connection ok: listen port %d.", LISTENER_PORT);
    return 0;
}
