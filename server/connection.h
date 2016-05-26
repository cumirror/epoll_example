#ifndef _CONNECTION_H
#define _CONNECTION_H

#include <time.h>

#include "slist.h"
#include "buffer.h"

#define MAX_CONNECTIONS 10240
#define LISTENER_PORT   8777
#define EXPIRE_TIME     10

typedef enum {
    CONNECTION_ACTIVE_NONE = 0,     //连接不能读写
    CONNECTION_ACTIVE_READ = 1,     //连接可读
    CONNECTION_ACTIVE_WRITE = 2     //连接可写
} Connection_active;

struct Connection {
    int fd;                     // socket fd
    int active;                 // record connection's status
    int remote;                 // remote server's IP
    time_t expire;              // expire time

    struct Buffer in_buffer;
    struct Buffer out_buffer;

    int (*read_process)(struct Connection* c);
    int (*write_process)(struct Connection* c);

    STAILQ_ENTRY(Connection) next;
};

STAILQ_HEAD(Connection_list, Connection);

void destroy_connection(struct Connection* conn);
int accept_event(struct Connection* conn);
int init_connection();

#endif
