#ifndef _LOCK_H
#define _LOCK_H

#include <pthread.h>

extern pthread_mutex_t Thread_mutex_lock;

static inline void thread_mutex_lock() {
    pthread_mutex_lock(&Thread_mutex_lock);
}

static inline void thread_mutex_unlock() {
    pthread_mutex_unlock(&Thread_mutex_lock);
}

#endif
