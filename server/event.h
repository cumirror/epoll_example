#ifndef _EVENT_H
#define _EVENT_H

#include "connection.h"

struct Event_module {
    char* name;
    int (*add_connection)(struct Connection* c, int active);
    int (*remove_connection)(struct Connection* c, int active);
    int (*delete_connection)(struct Connection* c);
    int (*init)();
    int (*process_events)();
    void (*done)();
};

int init_event();
void destroy_event();

extern struct Event_module Event;

#endif
