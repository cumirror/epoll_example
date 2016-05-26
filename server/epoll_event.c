#include <stdlib.h>
#include <syslog.h>
#include <errno.h>
#include <sys/epoll.h>
#include <unistd.h>

#include "log.h"
#include "lock.h"
#include "event.h"
#include "message.h"
#include "connection.h"

int Epoll_fd = -1;
struct epoll_event* Epoll_events = NULL;

/* This list hold connections which managed by epoll:
 *    when epoll_add_connection, we add connection to list
 *    when epoll_delete_connection, we remove connection from list
 */
struct Connection_list Connections = STAILQ_HEAD_INITIALIZER(Connections);

void connection_add(struct Connection* conn) {
    /* exclude listern fd */
    if (conn->expire < 0) {
        return;
    }

    conn->expire = time(NULL) + EXPIRE_TIME;
    thread_mutex_lock();
    STAILQ_INSERT_TAIL(&Connections, conn, next);
    thread_mutex_unlock();
}

void connection_delete(struct Connection* conn) {
    thread_mutex_lock();
    STAILQ_REMOVE(&Connections, conn, Connection, next);
    thread_mutex_unlock();
}

void connection_expired_check() {
    time_t now = time(NULL);
    struct Connection* tmp = NULL;
    struct Connection* conn = NULL;

    thread_mutex_lock();
    STAILQ_FOREACH_SAFE(conn, &Connections, next, tmp) {
        if (now > conn->expire) {
            connection_log(LOG_ERR, conn->remote, "connection(%p) expire", conn);
            STAILQ_REMOVE(&Connections, conn, Connection, next);
            epoll_ctl(Epoll_fd, EPOLL_CTL_DEL, conn->fd, NULL);
            destroy_connection(conn);
        }
    }
    thread_mutex_unlock();
}

int epoll_add_connection(struct Connection* conn, int active) {
    struct epoll_event ev;

    connection_add(conn);

    ev.events = EPOLLET;
    conn->active = active;

    if (active & CONNECTION_ACTIVE_READ) {
        ev.events = ev.events | EPOLLIN;
    }

    if (active & CONNECTION_ACTIVE_WRITE) {
        ev.events = ev.events | EPOLLOUT;
    }

    ev.data.ptr = conn;

    if (epoll_ctl(Epoll_fd, EPOLL_CTL_ADD, conn->fd, &ev) == -1) {
        /* epoll add failed, delete conn from list */
        connection_delete(conn);
        return -1;
    }

    return 0;
}

/* kernel versions should higher than 2.6.9 */
int epoll_delete_connection(struct Connection* conn) {
    connection_delete(conn);
    return epoll_ctl(Epoll_fd, EPOLL_CTL_DEL, conn->fd, NULL);
}

int epoll_remove_connection(struct Connection* conn, int active) {
    struct epoll_event ev;
    int pre_active = conn->active;

    if (active & CONNECTION_ACTIVE_READ) {
        conn->active = conn->active & (~CONNECTION_ACTIVE_READ);
    }

    if (active & CONNECTION_ACTIVE_WRITE) {
        conn->active = conn->active & (~CONNECTION_ACTIVE_WRITE);
    }

    if (conn->active == CONNECTION_ACTIVE_NONE) {
        return epoll_delete_connection(conn);
    }

    if (pre_active == conn->active) {
        return 0;
    }

    ev.events = EPOLLET;

    if (conn->active & CONNECTION_ACTIVE_READ) {
        ev.events = ev.events | EPOLLIN;
    }

    if (conn->active & CONNECTION_ACTIVE_WRITE) {
        ev.events = ev.events | EPOLLOUT;
    }

    ev.data.ptr = (void*)conn;

    if (epoll_ctl(Epoll_fd, EPOLL_CTL_MOD, conn->fd, &ev) == -1) {
        return -1;
    }

    return 0;
}

static void handle_events(struct epoll_event* events, int num) {
    int i = 0;

    for (; i < num; i++) {
        struct Connection* c = (struct Connection*)events[i].data.ptr;
        int flags = events[i].events;

        if (flags & EPOLLIN) {
            c->read_process(c);
        }

        if (flags & EPOLLOUT) {
            c->write_process(c);
        }
    }
}

int epoll_process_events() {
    int num = 0;

    connection_expired_check();

    if ((num = epoll_wait(Epoll_fd, Epoll_events, MAX_CONNECTIONS, -1)) == -1) {
        syslog(LOG_ERR, "epoll_wait error errno %d\n", errno);
        return -1;
    }

    handle_events(Epoll_events, num);

    /* try to wakeup message thread */
    wakeup_message_thread();

    return 0;
}

int epoll_init() {
    Epoll_fd = epoll_create(MAX_CONNECTIONS);

    if (Epoll_fd == -1) {
        return -1;
    }

    Epoll_events = (struct epoll_event*)malloc(sizeof(struct epoll_event) * MAX_CONNECTIONS);

    if (Epoll_events == NULL) {
        return -1;
    }

    return 0;
}

void epoll_done() {
    close(Epoll_fd);
    Epoll_fd = -1;
    free(Epoll_events);
    Epoll_events = NULL;
}
