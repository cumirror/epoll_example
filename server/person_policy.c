#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <netinet/in.h>

#include "message.h"

static int check_message_format(net_request_head_t* head, int len) {
    if (head->msgtype != NET_MESSAGE_UPDATE_PERSON_POLICY &&
            head->msgtype != NET_MESSAGE_QUE_PERSON_POLICY) {
        return -1;
    }

    if (head->msgtype == NET_MESSAGE_QUE_PERSON_POLICY) {
        return head->bodylen == 0 ? 0 : -2;
    }

    if (head->bodylen + sizeof(net_request_head_t) != (uint32_t)len) {
        return -3;
    }

    if ((head->bodylen % sizeof(net_person_policy_t)) != 0) {
        return -4;
    }

    return 0;
}

static int handle_rule(net_person_policy_t* netRule) {
    int option;
    uint32_t user_ip;
    uint32_t role_id;

    option = ntohl(netRule->option);
    user_ip = netRule->user_ip;
    role_id = ntohl(netRule->role_id);

    if (option == NET_OPTION_DEL) {
        if (netRule->user_ip == 0) {
            message_log(LOG_ERR, NET_MESSAGE_UPDATE_PERSON_POLICY,
                            "delete err: ip is 0.0.0.0");
            return -1;
        }
    } else if (option == NET_OPTION_ADD) {
        if (role_id || user_ip == 0) {
            message_log(LOG_ERR, NET_MESSAGE_UPDATE_PERSON_POLICY,
                            "add err: ip %x or id %u error", user_ip, role_id);
            return -1;
        }
    } else {
        message_log(LOG_ERR, NET_MESSAGE_UPDATE_PERSON_POLICY,
                        "rule option %d not support", option);
        return -1;
    }

    /* message process */

    return 0;
}

int set_personPolicy(net_request_head_t* head, int len, char** out, int* outlen) {
    int i, num, rsplen, ret = 0;
    net_person_policy_t* policy;
    net_response_head_t* response;

    rsplen = RESPONSE_MESSAGE_LEN(net_option_result_t, 1);
    response = (net_response_head_t*)get_pre_response_buffer(rsplen);
    memset(response, 0, rsplen);

    num = (head->bodylen) / sizeof(net_person_policy_t);
    policy = (net_person_policy_t*)(head + 1);

    for (i = 0; i < num; i++) {
        message_rule_log((char*)(policy + i), NET_MESSAGE_UPDATE_PERSON_POLICY);

        if ((ret = handle_rule(policy + i)) < 0) {
            break;
        }
    }

    response->msgresult = ret < 0 ? NET_OPTION_FAILED : NET_OPTION_SUCCESS;

    if (ret < 0) {
        net_option_result_t* result = (net_option_result_t*)(response + 1);
        result->index = htonl(i + 1);
        strncpy(result->reason, get_message_log(), sizeof(result->reason) - 1);
        response->bodylen += sizeof(net_option_result_t);
    }

    *out = (char*)response;
    *outlen = sizeof(net_response_head_t) + response->bodylen;

    return 0;
}

int query_personPolicy(net_request_head_t* head, int len, char** out, int* outlen) {
 
    return 0;
}

int handle_personPolicy_message(char* msg, int len, char** out, int* outlen) {
    net_request_head_t* head;
    int ret;

    if (msg == NULL || len <= 0 || *out != NULL || *outlen != 0) {
        message_log(LOG_ERR, 0, "handle person policy: parameter error");
        return -1;
    }

    head = (net_request_head_t*)msg;

    if ((ret = check_message_format(head, len)) < 0) {
        message_log(LOG_ERR, 0, "handle person policy: message format error %d", ret);
        return -2;
    }

    if (head->msgtype == NET_MESSAGE_QUE_PERSON_POLICY) {
        ret = query_personPolicy(head, len, out, outlen);
    } else {
        ret = set_personPolicy(head, len, out, outlen);
    }

    return ret;
}
