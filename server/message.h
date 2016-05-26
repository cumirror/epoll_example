#ifndef _MESSAGE_H
#define _MESSAGE_H

#include <stdint.h>
#include "net_message.h"
#include "connection.h"
#include "log.h"

void wakeup_message_thread();
int deliver_message(struct Connection* conn);
int message_set_to_kernel(int msg_type, void* msg, int msglen);
int message_get_from_kernel(int msg_type, void* buf, int* buflen);

int handle_personAcl_message(char* in, int ilen, char** out, int* olen);
int handle_whiteRule_message(char* msg, int len, char** out, int* outlen);
int handle_personPolicy_message(char* msg, int len, char** out, int* outlen);
int handle_rolePolicy_message(char* msg, int len, char** out, int* outlen);
int handle_configure_message(char* msg, int len, char** out, int* outlen);

int init_path(char* path);
int save_config();

char* get_pre_response_buffer(int len);

#endif
