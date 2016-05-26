#include <stdlib.h>
#include <string.h>

#include "buffer.h"

void init_buffer(struct Buffer* buf) {
    memset(buf, 0, sizeof(struct Buffer));
}

void free_buffer_data(struct Buffer* buf) {
    if (buf->data) {
        free(buf->data);
        init_buffer(buf);
    }
}

int alloc_buffer_data(struct Buffer* buf, int len) {
    char* data = NULL;

    if (buf->len >= len) {
        return 0;
    }

    if ((data = (char*)malloc(len)) == NULL) {
        return -1;
    }

    free_buffer_data(buf);
    buf->data = data;
    buf->len = len;
    buf->offset = 0;

    return 0;
}
