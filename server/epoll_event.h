#ifndef _EPOLL_EVENT_H
#define _EPOLL_EVENT_H

int epoll_add_connection(struct Connection* c, int active);
int epoll_remove_connection(struct Connection* c, int active);
int epoll_delete_connection(struct Connection* c);
int epoll_process_events();
int epoll_init();
void epoll_done();

#endif
