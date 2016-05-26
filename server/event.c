#include <stdio.h>
#include <unistd.h>

#include "event.h"
#include "epoll_event.h"

struct Event_module Event = {
    "epoll",
    epoll_add_connection,
    epoll_remove_connection,
    epoll_delete_connection,
    epoll_init,
    epoll_process_events,
    epoll_done
};

int init_event() {
    return Event.init();
}

void destroy_event() {
    Event.done();
}
