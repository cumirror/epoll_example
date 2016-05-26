#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <syslog.h>
#include <arpa/inet.h>

#include "net_message.h"

static char string1[64];
static char string2[64];
static char string3[64];
static char* ip_mask_string1(uint32_t ip, uint32_t mask) {
    uint8_t* p = (uint8_t*)&ip;

    sprintf(string1, "%d.%d.%d.%d/%d",
            p[0], p[1], p[2], p[3], mask);

    return string1;
}

static char* ip_mask_string2(uint32_t ip, uint32_t mask) {

    uint8_t* p = (uint8_t*)&ip;

    sprintf(string2, "%d.%d.%d.%d/%d",
            p[0], p[1], p[2], p[3], mask);

    return string2;
}

static char* ip_string(uint32_t ip) {

    uint8_t* p = (uint8_t*)&ip;

    sprintf(string3, "%d.%d.%d.%d",
            p[0], p[1], p[2], p[3]);

    return string3;
}

static char* logtype2string(int type) {
    char* p = NULL;

    switch (type) {
    case LOG_ERR:
        p = "[Error]";
        break;

    case LOG_WARNING:
        p = "[Warning]";
        break;

    case LOG_NOTICE:
        p = "[Notice]";
        break;

    case LOG_INFO:
        p = "[Info]";
        break;

    default:
        p = "[---]";
    }

    return p;
}

static char* msgtype2string(uint32_t type) {
    char* p = NULL;

    switch (type) {
    case NET_MESSAGE_UPDATE_WHITE_RULE:
        p = "update white rule";
        break;

    case NET_MESSAGE_RELOAD_WHITE_RULE:
        p = "reload white rule";
        break;

    case NET_MESSAGE_QUE_WHITE_RULE:
        p = "query white rule";
        break;

    case NET_MESSAGE_UPDATE_PERSON_ACL:
        p = "update person acl";
        break;

    case NET_MESSAGE_QUE_PERSON_ACL:
        p = "query person acl";
        break;

    case NET_MESSAGE_UPDATE_PERSON_POLICY:
        p = "update person policy";
        break;

    case NET_MESSAGE_QUE_PERSON_POLICY:
        p = "query person policy";
        break;

    case NET_MESSAGE_UPDATE_ROLE_POLICY:
        p = "update role policy";
        break;

    case NET_MESSAGE_RELOAD_ROLE_POLICY:
        p = "reload role policy";
        break;

    case NET_MESSAGE_QUE_ROLE_POLICY:
        p = "query role policy";
        break;

    case NET_MESSAGE_DEFAULT_PERMIT:
        p = "default permit";
        break;

    case NET_MESSAGE_DEFAULT_DROP:
        p = "default drop";
        break;

    case NET_MESSAGE_QUE_DEFAULT:
        p = "query default action";
        break;

    default:
        p = "---";
    }

    return p;
}

static char* result2string(uint32_t result) {
    char* p = NULL;

    switch (result) {
    case NET_OPTION_SUCCESS:
        p = "option success";
        break;

    case NET_OPTION_FAILED:
        p = "option failed";
        break;

    case NET_INTERNAL_ERR:
        p = "intenal error";
        break;

    default:
        p = "---";
    }

    return p;
}

static char* direction2string(uint16_t dir) {
    char* p = NULL;

    switch (dir) {
    case NET_DIRECTION_IN:
        p = "IN ";
        break;

    case NET_DIRECTION_OUT:
        p = "OUT";
        break;

    default:
        p = "---";
    }

    return p;
}

static char* option2string(uint32_t opt) {
    char* p = NULL;

    switch (opt) {
    case NET_OPTION_ADD:
        p = "add";
        break;

    case NET_OPTION_DEL:
        p = "del";
        break;

    case NET_OPTION_MOD:
        p = "mod";
        break;

    case NET_OPTION_DEL_ZHUNRU:
        p = "del zhunru";
        break;

    default:
        p = "---";
    }

    return p;
}

static char* action2string(uint32_t action) {
    char* p = NULL;

    switch (action) {
    case NET_ACTION_ACCEPT:
        p = "accept";
        break;

    case NET_ACTION_DROP:
        p = "drop";
        break;

    default:
        p = "---";
    }

    return p;
}

#ifdef DEBUG_DUMP
static void dump_person_acl(net_person_acl_t* acls, int num) {
    int i;

    printf("person acl num %d:\n", num);

    for (i = 0; i < num; i++) {
        printf("  %8d. [%s] { %s %s:%d-%d %s:%d-%d %d %s}\n",
               i + 1,
               option2string(ntohs(acls[i].option)),
               direction2string(ntohs(acls[i].dir)),
               ip_mask_string1(acls[i].sip, ntohl(acls[i].sip_mask_len)),
               ntohs(acls[i].sport_start), ntohs(acls[i].sport_end),
               ip_mask_string2(acls[i].dip, ntohl(acls[i].dip_mask_len)),
               ntohs(acls[i].dport_start), ntohs(acls[i].dport_end),
               ntohs(acls[i].proto), action2string(ntohs(acls[i].action)));
    }
}

static void dump_white_rule(net_white_rule_t* rules, int num) {
    int i;

    printf("white rule num %d:\n", num);

    for (i = 0; i < num; i++) {
        printf("  %8d.  [%u] [%s] { %s %s:%d-%d %s:%d-%d %d %s}\n",
               i + 1,
               ntohl(rules[i].place),
               option2string(ntohs(rules[i].option)),
               direction2string(ntohs(rules[i].dir)),
               ip_mask_string1(rules[i].sip, ntohl(rules[i].sip_mask_len)),
               ntohs(rules[i].sport_start), ntohs(rules[i].sport_end),
               ip_mask_string2(rules[i].dip, ntohl(rules[i].dip_mask_len)),
               ntohs(rules[i].dport_start), ntohs(rules[i].dport_end),
               ntohs(rules[i].proto), action2string(ntohs(rules[i].action)));
    }
}

static void dump_role_policy(net_role_policy_t* policies, int num) {
    int i;

    printf("role policy num %d:\n", num);

    for (i = 0; i < num; i++) {
        printf("  %8d.  [%s] [%u %u] { %s:%d-%d %s:%d-%d %d %s}\n",
               i + 1,
               option2string(ntohl(policies[i].option)),
               ntohl(policies[i].role_id), ntohl(policies[i].sort_num),
               ip_mask_string1(policies[i].sip, ntohl(policies[i].sip_mask_len)),
               ntohs(policies[i].sport_start), ntohs(policies[i].sport_end),
               ip_mask_string2(policies[i].dip, ntohl(policies[i].dip_mask_len)),
               ntohs(policies[i].dport_start), ntohs(policies[i].dport_end),
               ntohs(policies[i].proto), action2string(ntohs(policies[i].action)));
    }
}

static void dump_person_policy(net_person_policy_t* policy, int num) {
    int i;

    printf("person policy num %d:\n", num);

    for (i = 0; i < num; i++) {
        printf("  %8d.  [%s] { %s %u %.*s }\n",
               i + 1,
               option2string(ntohl(policy[i].option)),
               ip_string(policy[i].user_ip),
               ntohl(policy[i].role_id),
               (int)sizeof(policy[i].user_name),
               policy[i].user_name);
    }
}

static void dump_result(net_option_result_t* result) {
    printf("result info:\n\tindex: %u\n\treason: %s\n",
           ntohl(result->index), result->reason);
}

static void dump_default_action(uint32_t* action) {
    printf("default action: %s\n", action2string(ntohl(*action)));
}

static void dump_head(char* msg, int remote, int type) {
    if (type == 0) {
        net_request_head_t* request = (net_request_head_t*)msg;
        printf("req from [%s]: time(%s) key(%.*s) type(%s) bodylen(%u)\n",
               ip_string(remote), request->time, (int)sizeof(request->key), request->key,
               msgtype2string(ntohl(request->msgtype)), ntohl(request->bodylen));
    }

    if (type == 1) {
        net_response_head_t* response = (net_response_head_t*)msg;
        printf("rsp to [%s]: key(%.*s) result(%s) bodylen(%u)\n",
               ip_string(remote), (int)sizeof(response->key), response->key,
               result2string(ntohl(response->msgresult)), ntohl(response->bodylen));
    }
}

static void dump_body(char* msg, int type) {
    int num = 0;
    char* body = NULL;
    uint32_t msgtype = 0;
    uint32_t bodylen = 0;

    if (type == 0) {
        body = msg + sizeof(net_request_head_t);
        msgtype = ntohl(((net_request_head_t*)msg)->msgtype);
        bodylen = ntohl(((net_request_head_t*)msg)->bodylen);

        switch (msgtype) {
        case NET_MESSAGE_UPDATE_WHITE_RULE:
        case NET_MESSAGE_RELOAD_WHITE_RULE:
            num = bodylen / sizeof(net_white_rule_t);
            dump_white_rule((net_white_rule_t*)body, num);
            break;

        case NET_MESSAGE_UPDATE_PERSON_ACL:
            num = bodylen / sizeof(net_person_acl_t);
            dump_person_acl((net_person_acl_t*)body, num);
            break;

        case NET_MESSAGE_UPDATE_PERSON_POLICY:
            num = bodylen / sizeof(net_person_policy_t);
            dump_person_policy((net_person_policy_t*)body, num);
            break;

        case NET_MESSAGE_UPDATE_ROLE_POLICY:
        case NET_MESSAGE_RELOAD_ROLE_POLICY:
            num = bodylen / sizeof(net_role_policy_t);
            dump_role_policy((net_role_policy_t*)body, num);
            break;

        default:
            return ;
        }
    }

    if (type == 1) {
        body = msg + sizeof(net_response_head_t);
        msgtype = ntohl(((net_response_head_t*)msg)->msgtype);
        bodylen = ntohl(((net_response_head_t*)msg)->bodylen);

        switch (msgtype) {
        case NET_MESSAGE_UPDATE_WHITE_RULE:
        case NET_MESSAGE_RELOAD_WHITE_RULE:
        case NET_MESSAGE_UPDATE_PERSON_ACL:
        case NET_MESSAGE_UPDATE_PERSON_POLICY:
        case NET_MESSAGE_UPDATE_ROLE_POLICY:
        case NET_MESSAGE_RELOAD_ROLE_POLICY:
        case NET_MESSAGE_DEFAULT_PERMIT:
        case NET_MESSAGE_DEFAULT_DROP:
        case NET_MESSAGE_MAX:

            /* for response, bodylen will be zero when operation is success,
             * here we dump error msg */
            if (bodylen) {
                dump_result((net_option_result_t*)body);
            }

            break;

        case NET_MESSAGE_QUE_DEFAULT:
            dump_default_action((uint32_t*)body);
            break;

        case NET_MESSAGE_QUE_WHITE_RULE:
            num = bodylen / sizeof(net_white_rule_t);
            dump_white_rule((net_white_rule_t*)body, num);
            break;

        case NET_MESSAGE_QUE_PERSON_ACL:
            num = bodylen / sizeof(net_person_acl_t);
            dump_person_acl((net_person_acl_t*)body, num);
            break;

        case NET_MESSAGE_QUE_PERSON_POLICY:
            num = bodylen / sizeof(net_person_policy_t);
            dump_person_policy((net_person_policy_t*)body, num);
            break;

        case NET_MESSAGE_QUE_ROLE_POLICY:
            num = bodylen / sizeof(net_role_policy_t);
            dump_role_policy((net_role_policy_t*)body, num);
            break;

        default:
            return;
        }
    }

    return ;
}

void dump_request(char* request, int remote) {
    if (request == NULL) {
        return ;
    }

    dump_head(request, remote, 0);
    dump_body(request, 0);
}

void dump_response(char* response, int remote) {
    if (response == NULL) {
        return ;
    }

    dump_head(response, remote, 1);
    dump_body(response, 1);
}
#endif


/* log_buffer used by message module to record last error message */
#define LOG_BUFFER_SIZE 1024
char log_buffer[LOG_BUFFER_SIZE];

void message_head_log(char* msg, int remote) {
    net_request_head_t* request = (net_request_head_t*)msg;
    syslog(LOG_INFO, "req from [%s]: time(%s) key(%.*s) type(%s) bodylen(%u)",
           ip_string(remote), request->time, (int)sizeof(request->key), request->key,
           msgtype2string(ntohl(request->msgtype)), ntohl(request->bodylen));
}

void message_rule_log(char* msg, uint32_t msgtype) {

    switch (msgtype) {
    case NET_MESSAGE_UPDATE_WHITE_RULE:
    case NET_MESSAGE_RELOAD_WHITE_RULE: {
        net_white_rule_t* rule = (net_white_rule_t*)msg;
        syslog(LOG_INFO, " [%u] [%s] { %s %s:%d-%d %s:%d-%d %d %s}",
               ntohl(rule->place),
               option2string(ntohs(rule->option)),
               direction2string(ntohs(rule->dir)),
               ip_mask_string1(rule->sip, ntohl(rule->sip_mask_len)),
               ntohs(rule->sport_start), ntohs(rule->sport_end),
               ip_mask_string2(rule->dip, ntohl(rule->dip_mask_len)),
               ntohs(rule->dport_start), ntohs(rule->dport_end),
               ntohs(rule->proto), action2string(ntohs(rule->action)));
    }
    break;

    case NET_MESSAGE_UPDATE_PERSON_ACL: {
        net_person_acl_t* acl = (net_person_acl_t*)msg;
        syslog(LOG_INFO, " [%s] { %s %s:%d-%d %s:%d-%d %d %s}",
               option2string(ntohs(acl->option)),
               direction2string(ntohs(acl->dir)),
               ip_mask_string1(acl->sip, ntohl(acl->sip_mask_len)),
               ntohs(acl->sport_start), ntohs(acl->sport_end),
               ip_mask_string2(acl->dip, ntohl(acl->dip_mask_len)),
               ntohs(acl->dport_start), ntohs(acl->dport_end),
               ntohs(acl->proto), action2string(ntohs(acl->action)));
    }
    break;

    case NET_MESSAGE_UPDATE_PERSON_POLICY: {
        net_person_policy_t* policy = (net_person_policy_t*)msg;
        syslog(LOG_INFO, " [%s] { %s %u %.*s }",
               option2string(ntohl(policy->option)),
               ip_string(policy->user_ip),
               ntohl(policy->role_id),
               (int)sizeof(policy->user_name),
               policy->user_name);
    }
    break;

    case NET_MESSAGE_UPDATE_ROLE_POLICY:
    case NET_MESSAGE_RELOAD_ROLE_POLICY: {
        net_role_policy_t* policy = (net_role_policy_t*)msg;
        syslog(LOG_INFO, " [%s] [%u %u] { %s:%d-%d %s:%d-%d %d %s}",
               option2string(ntohl(policy->option)),
               ntohl(policy->role_id), ntohl(policy->sort_num),
               ip_mask_string1(policy->sip, ntohl(policy->sip_mask_len)),
               ntohs(policy->sport_start), ntohs(policy->sport_end),
               ip_mask_string2(policy->dip, ntohl(policy->dip_mask_len)),
               ntohs(policy->dport_start), ntohs(policy->dport_end),
               ntohs(policy->proto), action2string(ntohs(policy->action)));
    }
    break;

    default:
        return ;
    }
}

/* for message module */
int message_log(int type, uint32_t msgtype, const char* format, ...) {
    int len = 0;
    int used = 0;
    va_list args;

    used = snprintf(log_buffer, LOG_BUFFER_SIZE, "%s %s: ",
                    logtype2string(type), msgtype2string(msgtype));

    va_start(args, format);
    /* Try to write to local buffer.  */
    len = vsnprintf(log_buffer + used, LOG_BUFFER_SIZE - used, format, args);
    va_end(args);

    /* buffer is not enough. */
    if (len < 0 || (used + len) >= LOG_BUFFER_SIZE) {
        syslog(LOG_ERR, "set message log failed");
        return -1;
    }


    syslog(type, log_buffer);
    return 0;
}

char* get_message_log() {
    return log_buffer;
}

/* for connection module */
int connection_log(int type, int remote, const char* format, ...) {
    int len = 0;
    int used = 0;
    va_list args;
    char buffer[256] = {0};
    uint8_t* p = (uint8_t*)&remote;

    used = snprintf(buffer, 256, "%s %d.%d.%d.%d: ",
                    logtype2string(type), p[0], p[1], p[2], p[3]);

    va_start(args, format);
    len = vsnprintf(buffer + used, 256 - used, format, args);
    va_end(args);

    /* buffer is not enough. */
    if (len < 0 || (used + len) >= 256) {
        syslog(LOG_ERR, "set connection log failed(%d %d)", len, used);
        return -1;
    }

    syslog(type, buffer);
    return 0;
}
