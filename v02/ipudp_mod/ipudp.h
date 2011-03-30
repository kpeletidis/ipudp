#ifndef __IPUDP_H
#define __IPUDP_H 

#ifndef USERSPACE
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <net/netlink.h>
#include <net/genetlink.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/if_arp.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/list.h>
#include <linux/types.h>
#include <net/route.h>
#include <net/ip.h>
#include <net/ip6_route.h>
#include <net/ip6_fib.h>
#include <net/xfrm.h>
#include <linux/spinlock.h>

#else
#include <sys/types.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#endif

#define IPUDP_CONF_MAX_DEV 20
#define IPUDP_DEF_AF_OUT IPV4

#define IPUDP_CONF_MAX_TUN 100

#define MAX_IPUDP_DEV_NAME_LEN 12
#define IPV6_ADDR_LEN 16

enum 
ipudp_ret_code{
	IPUDP_OK = 0,
	IPUDP_BAD_MSG_FORMAT,
	IPUDP_BAD_CMD_SPEC,
	IPUDP_BAD_PARAMS,

	IPUDP_ERR_DEV_ALLOC,	
	IPUDP_ERR_DEV_MAX,
	IPUDP_ERR_DEV_NAME,
	IPUDP_ERR_DEV_REG,
	IPUDP_ERR_DEV_NOT_FOUND,

	IPUDP_ERR_TUN_BAD_PARAMS,
	IPUDP_ERR_TUN_MAX,
	IPUDP_ERR_TUN_NOT_FOUND,
	IPUDP_ERR_TUN_EXISTS,
	
	IPUDP_ERR_RULE_BAD_PARAMS,
	IPUDP_ERR_RULE_NOT_SUPPORTED,
	IPUDP_ERR_RULE_NOT_FOUND,
	IPUDP_ERR_RULE_MAX,
};

struct 
ipudp4hdr {
	struct iphdr ip;
	struct udphdr udp;
};

#define IPUDP4_HDR_LEN 20 + 8
#define IPUDP6_HDR_LEN 40 + 8

struct 
ipudp6hdr {
#ifndef USERSPACE
	struct ipv6hdr ip6;
#else
	struct ip6_hdr ip6;
#endif
	struct udphdr udp;
};

struct 
ipudp_conf {
	int max_dev_num; //XXX in 2 places
	int default_mode;
	int default_af_out;
};

/* module common struct */
typedef struct 
_ipudp_data {
	struct list_head * viface_list; //TODO not needed
	int viface_count;
	struct nf_hook_ops *nf_hook_ops_in;
	struct nf_hook_ops *nf_hook_ops_6_in;
	struct ipudp_conf conf;
	int max_dev_num;
} ipudp_data;

typedef enum
_ipudp_af_inet {
	IPV4 = 1,
	IPV6,
}ipudp_af_inet;

typedef enum
_ipudp_viface_mode {
	MODE_FIXED = 1,
	MODE_MULTI_V4,
	/* TODO EXTENSIBLE */
}ipudp_viface_mode;

/* ipdup genl stuff */
struct 
ipudp_nl_msg_attr{
	int is_string;
	int atype;
	void *data;
	int len;
};

typedef enum
_ipudp_nl_msg_type {
	MSG_REQUEST = 1,
	MSG_REPLY,
}ipudp_nl_msg_type;

/* cmd can be referred to: */ 
typedef enum
_ipudp_nl_cmd_spec {
	CMD_S_VIFACE = 1,
	CMD_S_TUN,
	CMD_S_RULE,
}ipudp_nl_cmd_spec;

//ipudp denl attributes
enum 
IPUDP_GNL_ATTRIBUTES{
	IPUDP_A_UNSPEC,
	IPUDP_A_STRING,
	IPUDP_A_CMD_SPEC,
	IPUDP_A_VIFACE_PARAMS,
	IPUDP_A_TUN_PARAMS,
	IPUDP_A_RULE_PARAMS,	
	IPUDP_A_LIST_PARAMS,
	IPUDP_A_RET_CODE,
	IPUDP_A_ERROR_DESC,
	__IPUDP_A_MSG_MAX,
};

// ipudp genl commands
typedef enum 
IPUDP_GNL_COMMANDS{
	IPUDP_C_UNSPEC, 	//do not touch, this is for the commands order
	IPUDP_C_UNSPEC2,	//do not touch, this is for the commands order TODO fix this - useless..
	IPUDP_C_ADD,
	IPUDP_C_DEL,
	IPUDP_C_GET,	
	IPUDP_C_CHANGE,
	IPUDP_C_LIST,
	__IPUDP_C_MAX,
}ipudp_genl_cmd;

/* list CDM params 
struct for IPUDP_C_LIST command */
typedef struct
_ipudp_nl_list_params{
	char dev_name[MAX_IPUDP_DEV_NAME_LEN + 1];
	int n_items;
}ipudp_nl_list_params;


#define IPUDP_C_MAX 			(__IPUDP_C_MAX - 1)
#define IPUDP_A_MSG_MAX			(__IPUDP_A_MSG_MAX - 1)

#define IPUDP_GNL_FAMILY_NAME 		"IPUDP_FAMILY"
#define IPUDP_GNL_FAMILY_VERSION 	1
/* end genl stuff */


/* ipudp module structures */
/* tunnel structures */
typedef struct
_ipudp_tun_params {
	//TODO TUN? TAP?
	ipudp_af_inet af;  	//ip v4 or v6. the following union
						//depend on this value...
	int dev_idx;		//idx of the underlying iface	
	union {
		struct {
			__u8 src[16]; 
			__u8 dest[16];
		}v6p;
		struct {
			__u32 src;
			__u32 dest;
		}v4p;
	} u;
	__u16 srcport;  	//udp src port - network byte order 
	__u16 destport;		//udp dest port - network byte order
	__u32 mark;			//netfilter fw mark
	__u32 tid;  		//local unique id for the tunnel
}ipudp_tun_params;

typedef struct
_ipudp_list_tun_item{
	struct list_head list;
	ipudp_tun_params tun;
}ipudp_list_tun_item;


typedef struct 
_ipudp_dev {	
	/* list pointer */
	struct list_head list;
	/* virtual iface device */
	struct net_device *dev; 
} ipudp_dev;

/* This struct is also the one filled and sent from userspace
in a genl command referring to a virtual device*/
typedef struct
_ipudp_viface_params{
	char name[MAX_IPUDP_DEV_NAME_LEN + 1]; //TODO remove it?
	ipudp_viface_mode mode;
	ipudp_af_inet af_out; //ip vers of outer header
}ipudp_viface_params;

/* ipudp forwarding rules structs */
#define IPUDP_CONF_MAX_RULE_MULTI_V4 1024

//this rule type binds a destination ipv4 address to a tunnel

//common fileds
typedef struct _ipudp_rule {
	struct list_head list;
	int type;	//same as ipudp_viface_mode
	int id;		//unique id for the rule
	int tun_id;	//tid of the related tunnel
	ipudp_tun_params *tun;
}ipudp_rule;

//MODE_MULTI_V4
typedef struct
_ipdup_rule_multi_v4 {
	struct list_head list;
	int type;	//same as ipudp_viface_mode
	int id;		//unique id for the rule
	int tun_id;	//tid of the related tunnel
	ipudp_tun_params *tun;
	//match
	__u32 dest;
} ipudp_rule_multi_v4;

#ifndef USERSPACE
typedef struct 
ipudp_dev_priv {
	ipudp_viface_params params;
	void * fw_rules; 			//forwarding rules
	int rule_count;
	int max_rule;
	struct list_head list_tun; 	//tunnel list
	spinlock_t tun_lock;
	int tun_count;
	int max_tun;
	/* virtual methods */
	void (*tun_xmit)(struct sk_buff *b, ipudp_tun_params *tun, struct net_device *dev);
	void (*tun_recv)(struct sk_buff *b, struct net_device *d);
	ipudp_tun_params* (*fw_lookup)(struct sk_buff *b, void *p);
	void (*fw_update)(struct sk_buff *b, void *p); //XXX does it make sense?
}ipudp_dev_priv;


/* function prototypes */
/* ipuudp_mod.c */
int ipudp_add_viface(ipudp_viface_params *);
int ipudp_del_viface(ipudp_viface_params *);

int ipudp_add_rule(ipudp_viface_params *, void *);
int ipudp_del_rule(ipudp_viface_params *, ipudp_rule *);


struct list_head * ipudp_get_viface_list(void);
int ipudp_get_viface_count(void);

int ipudp_bind_tunnel(ipudp_viface_params *, ipudp_tun_params *);
int ipudp_del_tun(ipudp_viface_params *, ipudp_tun_params *);
ipudp_dev_priv * ipudp_get_priv(char *);

/* ipudp_genl.c*/
int ipudp_genl_register(void);
void ipudp_genl_unregister(void);
#endif

#endif
