#ifndef _LOG_H
#define _LOG_H

#ifdef DEBUG_DUMP
void dump_request(char* request, int remote);
void dump_response(char* response, int remote);
#endif

void message_head_log(char* msg, int remote);
void message_rule_log(char* msg, uint32_t msgtype);
int message_log(int type, uint32_t msgtype, const char* format, ...);
char* get_message_log();

int connection_log(int type, uint32_t msgtype, const char* format, ...);

#endif
