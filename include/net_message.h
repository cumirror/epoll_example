#ifndef _NET_MESSAGE_H__
#define _NET_MESSAGE_H__

enum net_messge_type_ {
    NET_MESSAGE_UPDATE_WHITE_RULE = 1,
    NET_MESSAGE_RELOAD_WHITE_RULE,
    NET_MESSAGE_QUE_WHITE_RULE,

    NET_MESSAGE_UPDATE_PERSON_ACL,
    NET_MESSAGE_QUE_PERSON_ACL,

    NET_MESSAGE_UPDATE_PERSON_POLICY,
    NET_MESSAGE_QUE_PERSON_POLICY,

    NET_MESSAGE_UPDATE_ROLE_POLICY,
    NET_MESSAGE_RELOAD_ROLE_POLICY,
    NET_MESSAGE_QUE_ROLE_POLICY,

    NET_MESSAGE_DEFAULT_PERMIT,
    NET_MESSAGE_DEFAULT_DROP,
    NET_MESSAGE_QUE_DEFAULT,

    NET_MESSAGE_MAX = 0xFFFF
};

enum net_direction_type_ {
    NET_DIRECTION_IN = 1,
    NET_DIRECTION_OUT,
};

enum net_action_type_ {
    NET_ACTION_ACCEPT = 2,
    NET_ACTION_DROP,
};

enum net_option_type_ {
    NET_OPTION_ADD = 1,
    NET_OPTION_DEL,
    NET_OPTION_MOD,
    NET_OPTION_DEL_ZHUNRU,
};

enum net_result_type_ {
    NET_OPTION_SUCCESS = 0,
    NET_OPTION_FAILED,
    NET_INTERNAL_ERR,
};

typedef struct net_request_head_ {
    uint8_t time[16];
    uint8_t key[8];
    uint32_t msgtype;
    uint32_t bodylen;
} net_request_head_t;

typedef struct net_response_head_ {
    uint8_t key[8];
    int32_t msgtype;
    uint32_t msgresult;
    uint32_t bodylen;
} net_response_head_t;

typedef struct net_white_rule_ {
    uint16_t option;
    uint16_t dir;
    uint32_t place;
    uint16_t proto;
    uint16_t action;
    uint32_t sip;
    uint32_t sip_mask_len;
    uint16_t sport_start;
    uint16_t sport_end;
    uint32_t dip;
    uint32_t dip_mask_len;
    uint16_t dport_start;
    uint16_t dport_end;
} net_white_rule_t;

typedef struct net_person_acl_ {
    uint16_t option;
    uint16_t dir;
    uint16_t proto;
    uint16_t action;
    uint32_t sip;
    uint32_t sip_mask_len;
    uint16_t sport_start;
    uint16_t sport_end;
    uint32_t dip;
    uint32_t dip_mask_len;
    uint16_t dport_start;
    uint16_t dport_end;
} net_person_acl_t;

typedef struct net_person_policy_ {
    uint32_t option;
    uint32_t user_ip;
    uint32_t role_id;
    char     user_name[32];
} net_person_policy_t;

typedef struct net_role_policy_ {
    uint32_t option;
    uint32_t role_id;
    uint32_t sort_num;
    uint16_t proto;
    uint16_t action;
    uint32_t sip;
    uint32_t sip_mask_len;
    uint16_t sport_start;
    uint16_t sport_end;
    uint32_t dip;
    uint32_t dip_mask_len;
    uint16_t dport_start;
    uint16_t dport_end;
} net_role_policy_t;

typedef struct net_option_result_ {
    uint32_t index;
    char     reason[128];
} net_option_result_t;

#define REQUEST_MESSAGE_LEN(item_type, num) \
    (sizeof(net_request_head_t) + sizeof(item_type) * (num))

#define RESPONSE_MESSAGE_LEN(item_type, num) \
    (sizeof(net_response_head_t) + sizeof(item_type) * (num))

#endif
