#ifndef _BUFFER_H
#define _BUFFER_H

struct Buffer {
    int len;
    int offset;
    char* data;
};

void init_buffer(struct Buffer* buf);

int alloc_buffer_data(struct Buffer* buf, int len);

void free_buffer_data(struct Buffer* buf);

#endif
