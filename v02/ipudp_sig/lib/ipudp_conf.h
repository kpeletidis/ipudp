#ifndef IPUDP_CONF_H_
#define IPUDP_CONF_H_


#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <net/if.h>  
#include <sys/types.h>
#include <unistd.h>

#include <ipudp.h> //kernel header

#define MAX_BUF_LEN 1024

//TODO use ipudp_nl_cmd_spec
typedef enum 
_cmd_add_type {
	VIFACE = 1,
	TUN,
	TSA,
	RULE,
}cmd_add_type;

struct genl_msg{
	struct nlmsghdr n;
	struct genlmsghdr g;
	char buf[MAX_BUF_LEN];
};

#define GENLMSG_DATA(glh) 		((void *)(NLMSG_DATA(glh) + GENL_HDRLEN))
#define GENLMSG_DATALEN(glh) 		(NLMSG_PAYLOAD(glh, 0) - GENL_HDRLEN)
#define GENLMSG_NLA_NEXT(na) 		(((void *)(na)) + NLA_ALIGN(na->nla_len))
#define GENLMSG_NLA_DATA(na) 		((void *)((char*)(na) + NLA_HDRLEN))
#define GENLMSG_NLA_DATALEN(na) 	(na->nla_len - NLA_HDRLEN - 1)

typedef __u8  u8;
typedef __u16 u16;
typedef __u32 u32;

int ipudp_genl_client_init();
void parse_lst_nl_attrs();
void parse_nl_attrs();
void printResponse(const unsigned int);

/*CMDS*/
int do_cmd_add_viface(ipudp_viface_params *);
int do_cmd_del_viface(ipudp_viface_params *);

int do_cmd_add_tun(ipudp_viface_params *, ipudp_tun_params *);
int do_cmd_del_tun(ipudp_viface_params *, ipudp_tun_params *);

int do_cmd_list(char *, ipudp_nl_cmd_spec);

int do_cmd_add_rule(ipudp_viface_params *, void *, int);
int do_cmd_del_rule(ipudp_viface_params *, ipudp_rule *);

/* utlis */
int get_iface_idx_by_name(char *);
int get_iface_name_by_idx(int, char *);
#endif /* UPMT_USER_H_ */
