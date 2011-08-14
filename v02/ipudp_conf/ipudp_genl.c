
//#include "ipudp_stamp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <arpa/inet.h>
#include <errno.h>
#include "ipudp_conf.h"

int 	nl_sd;
int 	ipudp_fam_id;
struct 	genl_msg req, resp;

/*TODO move this inside a the functions? */
struct 	nlattr *nl_attr[IPUDP_A_MSG_MAX + 1];

/* XXX TODO XXX group the code, use sub-functions */

void print_response(const unsigned int);
static int receive_response(void);

static void 
set_nl_attr(struct nlattr *na, const unsigned int type, 
		const void *data, const unsigned int len){
	int length = len + 2;
	na->nla_type = type;
	na->nla_len = length + NLA_HDRLEN; //message length
	memcpy(GENLMSG_NLA_DATA(na), data, length);
}

static void
__print_ipudp_error(int err) {
	switch(err) {
		case IPUDP_BAD_MSG_FORMAT:
			printf("error: bad ipudp genl message format\n");
			break;
		case IPUDP_BAD_CMD_SPEC:
			printf("error: bad ipudp genl command spedification\n");
			break;
		case IPUDP_BAD_PARAMS:
			printf("error: bad ipudp genl message attribute\n");
			break;
		case IPUDP_ERR_DEV_ALLOC:	
			printf("error: couldn't allocate device\n");
			break;
		case IPUDP_ERR_DEV_MAX:
			printf("error: too many devices\n");
			break;
		case IPUDP_ERR_DEV_NAME:
			printf("error: bad device name\n");
			break;
		case IPUDP_ERR_DEV_REG:
			printf("error: coudn't register device\n");
			break;
		case IPUDP_ERR_DEV_NOT_FOUND:
			printf("error: device not found\n");
			break;
		case IPUDP_ERR_TUN_BAD_PARAMS:
			printf("error: bad tunnel parameters\n");
			break;
		case IPUDP_ERR_TUN_MAX:
			printf("error: too many ipudp tunnels\n");
			break;
		case IPUDP_ERR_TUN_NOT_FOUND:
			printf("error: tunnel not found\n");
			break;
		case IPUDP_ERR_TUN_EXISTS:
			printf("error: tunnel exists\n");
			break;
		case IPUDP_ERR_RULE_BAD_PARAMS:
			printf("error: bad rule arguments\n");
			break;
		case IPUDP_ERR_RULE_NOT_SUPPORTED:
			printf("error: rules not supported by device\n");
			break;
		case IPUDP_ERR_RULE_NOT_FOUND:
			printf("error: rule not found\n");
			break;
		case IPUDP_ERR_RULE_MAX:
			printf("error: max rule number exceeded\n");
			break;
		default:
			printf("error: unknown error\n");
			break;
	}
}	

static void 
reset_nl_attrs(void){
	int i;
	for(i=0; i<=IPUDP_A_MSG_MAX; i++){
		nl_attr[i] = NULL;
	}
}

void 
parse_nl_attrs(void){
	reset_nl_attrs();

	unsigned int n_attrs = 0;
	struct nlattr *na;
	unsigned int data_len = GENLMSG_DATALEN(&resp.n);

	na = (struct nlattr *) GENLMSG_DATA(&resp);
	nl_attr[na->nla_type] = na;
	n_attrs++;
	data_len = data_len - NLA_ALIGN(na->nla_len);

	while(data_len > 0){
		na = (struct nlattr *) GENLMSG_NLA_NEXT(na);
		nl_attr[na->nla_type] = na;
		n_attrs++;
		data_len = data_len - NLA_ALIGN(na->nla_len);
	}
	if(n_attrs > IPUDP_A_MSG_MAX) 
		printf("parse_nl_attributes: to many attributes\n");
}


static int 
create_nl_socket(const int groups){
	//socklen_t addr_len;
	int fd;
	struct sockaddr_nl local;

	fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	if (fd < 0){
		perror("unable to create netlink socket");
		return -1;
	}

	memset(&local, 0, sizeof(local));
	local.nl_family = AF_NETLINK;
	local.nl_groups = groups;
	local.nl_pid 	= getpid();

#if 0
	if (bind(fd, (struct sockaddr *) &local, sizeof(local)) < 0){
		close(fd);
		perror("unable to bind netlink socket");
		return -1;
	}
#endif

	nl_sd = fd;
	return 0;
}

static int 
sendto_fd(int s, const char *buf, int bufLen){
	struct sockaddr_nl nladdr;
	int r;

	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;

	while ((r = sendto(s, buf, bufLen, 0, 
		(struct sockaddr *) &nladdr, sizeof(nladdr))) < bufLen){
		if (r > 0) {
			buf += r;
			bufLen -= r;
		} else if (errno != EAGAIN) return -1;
	}
	return 0;
}

static int 
get_family_id(void){
	struct nlattr *na;
	int id;//, rep_len;

	req.n.nlmsg_len 	= NLMSG_LENGTH(GENL_HDRLEN);
	req.n.nlmsg_type	= GENL_ID_CTRL;
	req.n.nlmsg_flags 	= NLM_F_REQUEST;
	req.n.nlmsg_seq 	= 0;
	req.n.nlmsg_pid 	= getpid();
	req.g.cmd 		= CTRL_CMD_GETFAMILY;
	req.g.version 		= 0x1;

	na = (struct nlattr *) GENLMSG_DATA(&req);
	set_nl_attr(na, CTRL_ATTR_FAMILY_NAME, 
		IPUDP_GNL_FAMILY_NAME, strlen(IPUDP_GNL_FAMILY_NAME));
	
	req.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);

	if (sendto_fd(nl_sd, (char *) &req, req.n.nlmsg_len) < 0) 
		return -1;

	if (receive_response() < 0) return -1;

	na = (struct nlattr *) GENLMSG_DATA(&resp);
	na = (struct nlattr *) GENLMSG_NLA_NEXT(na);

	if (na->nla_type == CTRL_ATTR_FAMILY_ID) {
		id = *(u16 *) GENLMSG_NLA_DATA(na);
	}

	ipudp_fam_id = id;
	return 0;
}


static int 
receive_response(void){
	memset(resp.buf, 0, MAX_BUF_LEN);
	
	int l = recv(nl_sd, &resp, sizeof(resp), 0);

	if (resp.n.nlmsg_type == NLMSG_ERROR) {
		printf("ipudp_genl: NLMSG_ERROR received\n");
		return -1;
	}

	if (l < 0) {
		printf("ipudp_genl: ERROR genl mesg length < 0\n");
		return -1;
	}

	if (!NLMSG_OK((&resp.n), l)) {
		printf("iudp_genl: not NLMSG_OK\n");
		return -1;
	}

	//TODO check NL_F_REQUEST 
	//TODO check Sequence Number

	if(resp.g.cmd == 1) return 0;  //???? TODO

	
	return 0;
}

static void * 
get_nl_data(const unsigned int type){
	if(nl_attr[type] == NULL) return NULL;
	void *data = GENLMSG_NLA_DATA(nl_attr[type]);
	return data;
}

int 
ipudp_genl_client_init(){
	int err;

	if ((err = create_nl_socket(0))){
		printf("ipudp_genl_client_init: create_nl_socket error\n");
		return err;
	}
	if ((err = get_family_id())){
		printf("ipudp_genl_client_init: get_family_id error\n");
		return err;
	}

	return 0;
}

/*
static void 
print_nl_attr(struct nlattr *na){
	if(na == NULL){
		printf("\nAttr NULL");
		return;
	}
	//printf("\nAttr type: %u", na->nla_type);
	//printf("\nAttr len: %u", na->nla_len);
	//printf("\nContentLen: %d", GENLMSG_NLA_DATALEN(na));
	//void *data = GENLMSG_NLA_DATA(na);
	//if(na->nla_type == IPUDP_A_MSG_TYPE){
	//	printf(" %s", (char *)data);
	//}

	//else if(na->nla_type == IPUDP_A_PAFT_KEY) 	print_ipudp_key((struct ipudp_key *)data);
	//else if(na->nla_type == IPUDP_A_TUN_TID) 	printf("\n\t TID: %u", *((unsigned int *)data));
	//else if(na->nla_type == IPUDP_A_TUN_PARAM) 	print_ipudp_tun_param((struct tun_param *)data);
	//else if(na->nla_type == IPUDP_A_TUN_LOCAL) 	print_ipudp_tun_local((struct tun_local *)data);
	//else if(na->nla_type == IPUDP_A_UNSPEC) 		printf("\nContent: %s", (char *)data);
	//else printf("\n Content - unknown format");
}
*/
/*
static void 
print_nl_attrs(void){
	int i;
	for(i=0; i<=IPUDP_A_MSG_MAX; i++){
		if(nl_attr[i] != NULL) print_nl_attr(nl_attr[i]);
	}
}
*/

int 
do_cmd_add_viface(ipudp_viface_params *p){
	struct nlattr *na;
	//struct sockaddr_nl nladdr;
	int ret;
	ipudp_nl_cmd_spec cmd_spec = CMD_S_VIFACE;
	
	/* fill the header */
	req.n.nlmsg_len 	= NLMSG_LENGTH(GENL_HDRLEN);
	req.n.nlmsg_type 	= ipudp_fam_id;
	req.n.nlmsg_flags 	= NLM_F_REQUEST;
	req.n.nlmsg_seq 	= 0;
	req.n.nlmsg_pid 	= getpid();
	req.g.cmd 		= IPUDP_C_ADD;


	/* first attribute - cmd specification: DEV */
	na = (struct nlattr *) GENLMSG_DATA(&req);
	set_nl_attr(na, IPUDP_A_CMD_SPEC, &cmd_spec, sizeof(int));
	req.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);

	/* second attribute - viface params */
	na = (struct nlattr *) GENLMSG_NLA_NEXT(na);
	set_nl_attr(na, IPUDP_A_VIFACE_PARAMS, p, sizeof(ipudp_viface_params));
	req.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);

	/* send nl message */
	if (sendto_fd(nl_sd, (char *) &req, req.n.nlmsg_len) < 0)  {
		printf("ipudp_genl: error sending genl message\n");
		return -1;
	}

	if ((receive_response()) < 0) {
		printf("receive_response error!\n");
		return -1;
	}
	
	parse_nl_attrs();
	/* parse the response: 
	in this case we expect a msg without attributes (OK)
	or a message with IPUDP_A_ERROR_DESC (an error occurred)*/
	if ((ret = *(int *)get_nl_data(IPUDP_A_RET_CODE)))
		__print_ipudp_error(ret);
	else {
		p = (ipudp_viface_params *) get_nl_data(IPUDP_A_VIFACE_PARAMS);
		printf("device %s successfully added\n", p->name);
	}

	return ret;
}

int 
do_cmd_del_tun(ipudp_viface_params *q,ipudp_tun_params *p) {
	struct nlattr *na;
	int ret;
	ipudp_nl_cmd_spec cmd_spec = CMD_S_TUN;
	
	/* fill the header */
	req.n.nlmsg_len 	= NLMSG_LENGTH(GENL_HDRLEN);
	req.n.nlmsg_type 	= ipudp_fam_id;
	req.n.nlmsg_flags 	= NLM_F_REQUEST;
	req.n.nlmsg_seq 	= 0;
	req.n.nlmsg_pid 	= getpid();
	req.g.cmd 			= IPUDP_C_DEL;


	/* first attribute - cmd specification: TUN */
	na = (struct nlattr *) GENLMSG_DATA(&req);
	set_nl_attr(na, IPUDP_A_CMD_SPEC, &cmd_spec, sizeof(int));
	req.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);

	/* second attribute - tun params */
	na = (struct nlattr *) GENLMSG_NLA_NEXT(na);
	set_nl_attr(na, IPUDP_A_TUN_PARAMS, p, sizeof(ipudp_tun_params));
	req.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);

	/* third attribute - viface params */
	na = (struct nlattr *) GENLMSG_NLA_NEXT(na);
	set_nl_attr(na, IPUDP_A_VIFACE_PARAMS, q, sizeof(ipudp_viface_params));
	req.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);

	/* send nl message */
	if (sendto_fd(nl_sd, (char *) &req, req.n.nlmsg_len) < 0)  {
		printf("ipudp_genl: error sending genl message\n");
		return -1;
	}

	if ((receive_response()) < 0) {
		printf("receive_response error!\n");
		return -1;
	}

	parse_nl_attrs();
	
	if ((ret = *(int *)get_nl_data(IPUDP_A_RET_CODE)))	
		__print_ipudp_error(ret);
	else
		printf("tunnel %d for viface %s successfully removed\n", p->tid, q->name);

	return 0;
}


//del rule by index
int 
do_cmd_del_rule(ipudp_viface_params *q, ipudp_rule *p) {
	struct nlattr *na;
	int ret;
	ipudp_nl_cmd_spec cmd_spec = CMD_S_RULE;
	
	/* fill the header */
	req.n.nlmsg_len 	= NLMSG_LENGTH(GENL_HDRLEN);
	req.n.nlmsg_type 	= ipudp_fam_id;
	req.n.nlmsg_flags 	= NLM_F_REQUEST;
	req.n.nlmsg_seq 	= 0;
	req.n.nlmsg_pid 	= getpid();
	req.g.cmd 			= IPUDP_C_DEL;


	/* first attribute - cmd specification: RULE */
	na = (struct nlattr *) GENLMSG_DATA(&req);
	set_nl_attr(na, IPUDP_A_CMD_SPEC, &cmd_spec, sizeof(int));
	req.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);

	/* second attribute - RULE params */
	na = (struct nlattr *) GENLMSG_NLA_NEXT(na);
	set_nl_attr(na, IPUDP_A_RULE_PARAMS, p, sizeof(ipudp_rule));
	req.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);

	/* third attribute - viface params */
	na = (struct nlattr *) GENLMSG_NLA_NEXT(na);
	set_nl_attr(na, IPUDP_A_VIFACE_PARAMS, q, sizeof(ipudp_viface_params));
	req.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);

	/* send nl message */
	if (sendto_fd(nl_sd, (char *) &req, req.n.nlmsg_len) < 0)  {
		printf("ipudp_genl: error sending genl message\n");
		return -1;
	}

	if ((receive_response()) < 0) {
		printf("receive_response error!\n");
		return -1;
	}

	parse_nl_attrs();
	
	if ((ret = *(int *)get_nl_data(IPUDP_A_RET_CODE)))	
		__print_ipudp_error(ret);
	else
		printf("rule %d for viface %s successfully removed\n", p->id, q->name);

	return 0;
}

int 
do_cmd_del_viface(ipudp_viface_params *p){
	struct nlattr *na;
	//struct sockaddr_nl nladdr;
	int ret;
	ipudp_nl_cmd_spec cmd_spec = CMD_S_VIFACE;
	
	/* fill the header */
	req.n.nlmsg_len 	= NLMSG_LENGTH(GENL_HDRLEN);
	req.n.nlmsg_type 	= ipudp_fam_id;
	req.n.nlmsg_flags 	= NLM_F_REQUEST;
	req.n.nlmsg_seq 	= 0;
	req.n.nlmsg_pid 	= getpid();
	req.g.cmd 			= IPUDP_C_DEL;

	/* first attribute - cmd specification: DEV */
	na = (struct nlattr *) GENLMSG_DATA(&req);
	set_nl_attr(na, IPUDP_A_CMD_SPEC, &cmd_spec, sizeof(int));
	req.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);

	/* second attribute - viface params */
	na = (struct nlattr *) GENLMSG_NLA_NEXT(na);
	set_nl_attr(na, IPUDP_A_VIFACE_PARAMS, p, sizeof(ipudp_viface_params));
	req.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);

	/* send nl message */
	if (sendto_fd(nl_sd, (char *) &req, req.n.nlmsg_len) < 0)  {
		printf("ipudp_genl: error sending genl message\n");
		return -1;
	}

	if ((receive_response()) < 0) {
		printf("receive_response error!\n");
		return -1;
	}

	parse_nl_attrs();
	
	if ((ret = *(int *)get_nl_data(IPUDP_A_RET_CODE)))	
		__print_ipudp_error(ret);
	else {
		p = (ipudp_viface_params *) get_nl_data(IPUDP_A_VIFACE_PARAMS);
		printf("viface %s successfully removed\n", p->name);
	}


	return ret;
}

static void 
__print_viface_params(ipudp_viface_params *p) {
	char mode[64], af[64];
	
	memset(mode,0,64);
	memset(af,0,64);

	switch(p->mode) {
		case MODE_FIXED:
			strcat(mode,"fixed");
			break;
		case MODE_MULTI_V4:
			strcat(mode,"multi_v4");
			break;

		//TODO extend it
		
		default:
			printf("Unknown viface mode %d\n", p->mode);
			return;
	}

	switch(p->af_out) {
		case IPV4:
			strcat(af,"ipv4");
			break;
		case IPV6:
			strcat(af,"ipv6");
			break;
	
		default:
			printf("unknown af_out\n");
			return;
	}
	
	printf("%s, encap header %s, encap mode %s\n",p->name, af, mode);

}

static void 
__print_tun_params(ipudp_tun_params * data) {
	char ip_src[64];
	char ip_dest[64];
	char temp[64];
	char ifname[IFNAMSIZ];

	memset(ip_src, 0, 64);
	memset(ip_dest, 0, 64);
	memset(temp, 0, 64);
	memset(ifname, 0, IFNAMSIZ);

	if (data->af == IPV4) {
		if (!data->dev_idx)
			inet_ntop(AF_INET, &(data->u.v4p.src), ip_src, 64);
		inet_ntop(AF_INET, &(data->u.v4p.dest), ip_dest, 64);
	}
	else if (data->af == IPV6) {
		if (!data->dev_idx)
			inet_ntop(AF_INET6, &(data->u.v6p.src), ip_src, 64);
		inet_ntop(AF_INET6, &(data->u.v6p.dest), ip_dest, 64);
	}
	else {
		printf("unknown outer af family\n");
		return;
	}

	if (data->dev_idx) {
		if (get_iface_name_by_idx(data->dev_idx, ifname) < 0) {
			sprintf(temp,"dev idx %d", data->dev_idx);
		}
		else 	
			sprintf(temp,"dev %s", ifname);
	}
	else
		sprintf(temp,"src %s", ip_src);

	printf("tid %d, %s, dest %s, sport %d, dport %d\n",
			data->tid, temp, ip_dest, ntohs(data->srcport), ntohs(data->destport));

	return;
}


static void 
__print_rule_params(ipudp_rule * data) {
	switch(data->type) {
		case MODE_MULTI_V4:{
			char addr[16];
			ipudp_rule_multi_v4 *p = (ipudp_rule_multi_v4 *)data;

			inet_ntop(AF_INET, &(p->dest), addr, 16);

			printf("rule %d, dest %s, tun id %d\n", p->id, addr, p->tun_id);

			break;
		}
		default:
			//can't happen
			break;
	}
}

static void 
__print_list_attr(ipudp_nl_cmd_spec cmd_spec, void *data) {

	switch(cmd_spec) {
		case CMD_S_VIFACE:
			__print_viface_params((ipudp_viface_params *)data);
			break;
		case CMD_S_TUN:
			__print_tun_params((ipudp_tun_params *)data);
			break;
		case CMD_S_RULE:
			__print_rule_params((ipudp_rule *)data);
			break;
		default: //can't happen...
			printf("unknown cmd_type %d\n",cmd_spec);
			break;
	}
}

static int 
__parse_list(ipudp_nl_cmd_spec cmd_spec) {
	int ret = 0;
	int ret_code;
	void *data;
	ipudp_nl_list_params *list_params;
	unsigned int n_attrs = 0;
	struct nlattr *na;
	unsigned int data_len = GENLMSG_DATALEN(&resp.n);

	/* get return code */
	na = (struct nlattr *) GENLMSG_DATA(&resp);
	data = GENLMSG_NLA_DATA(na);
	n_attrs++;
	data_len = data_len - NLA_ALIGN(na->nla_len);
	
	if (na->nla_type != IPUDP_A_RET_CODE) { 
		printf("do_cmd_list: expected IPUDP_A_RET_CODE attribute\n");
		return 1;
	}
	ret_code = *(int*)data;
	
	if (ret_code) {
			__print_ipudp_error(ret_code);
			return 1;
	}

	/* get list params */
	na = (struct nlattr *) GENLMSG_NLA_NEXT(na);
	data = GENLMSG_NLA_DATA(na);
	n_attrs++;
	data_len = data_len - NLA_ALIGN(na->nla_len);
	list_params = (ipudp_nl_list_params *)data;


	if (na->nla_type != IPUDP_A_LIST_PARAMS){
		printf("do_cmd_list: error, expected IPUDP_A_LIST_PARAMS attribute\n");
		return 1;
	}

	/*
	if (cmd_spec != CMD_S_VIFACE) 
		printf("list type %d for virtual interface %s, n_intems: %d\n", cmd_spec, 
				list_params->dev_name, list_params->n_items);	
	else 
		printf("virtual interface list, n_intems: %d\n", list_params->n_items);	
	*/

	while(data_len > 0){
		na = (struct nlattr *) GENLMSG_NLA_NEXT(na);
		data = GENLMSG_NLA_DATA(na);
		n_attrs++;
		data_len = data_len - NLA_ALIGN(na->nla_len);

		__print_list_attr(cmd_spec, data);
	}

	if (n_attrs != 2 + list_params->n_items) {
		printf("do_cmd_list: warning, expected %d list items\n", list_params->n_items);
	}

	return ret;
}

int do_cmd_list(char *viface_name, ipudp_nl_cmd_spec cmd_spec) {
	struct nlattr *na;
	int ret;
	ipudp_nl_list_params p;

	memset(&p,0,sizeof(p));
	
	if (viface_name) 
		memcpy(&p.dev_name,viface_name, strlen(viface_name));

	/* fill the header */
	req.n.nlmsg_len 	= NLMSG_LENGTH(GENL_HDRLEN);
	req.n.nlmsg_type 	= ipudp_fam_id;
	req.n.nlmsg_flags 	= NLM_F_REQUEST;
	req.n.nlmsg_seq 	= 0;
	req.n.nlmsg_pid 	= getpid();
	req.g.cmd 		= IPUDP_C_LIST;

	/* first attribute - cmd specification */
	na = (struct nlattr *) GENLMSG_DATA(&req);
	set_nl_attr(na, IPUDP_A_CMD_SPEC, &cmd_spec, sizeof(int));
	req.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);

	/* second attribute - list params */
	na = (struct nlattr *) GENLMSG_NLA_NEXT(na);
	set_nl_attr(na, IPUDP_A_LIST_PARAMS, &p, sizeof(p));
	req.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);

	/* send nl message */
	if (sendto_fd(nl_sd, (char *) &req, req.n.nlmsg_len) < 0)  {
		printf("ipudp_genl: error sending genl message\n");
		return -1;
	}

	if ((receive_response()) < 0) {
		printf("receive_response error!\n");
		return -1;
	}

	/* TODO */
	ret = __parse_list(cmd_spec);

	return ret;
}

int 
do_cmd_add_tun(ipudp_viface_params *v, ipudp_tun_params *p){
	struct nlattr *na;
	//struct sockaddr_nl nladdr;
	int ret;
	ipudp_nl_cmd_spec cmd_spec = CMD_S_TUN;
	ipudp_tun_params *t;
	
	/* fill the header */
	req.n.nlmsg_len 	= NLMSG_LENGTH(GENL_HDRLEN);
	req.n.nlmsg_type 	= ipudp_fam_id;
	req.n.nlmsg_flags 	= NLM_F_REQUEST;
	req.n.nlmsg_seq 	= 0;
	req.n.nlmsg_pid 	= getpid();
	req.g.cmd 			= IPUDP_C_ADD;


	/* first attribute - cmd specification: TUN */
	na = (struct nlattr *) GENLMSG_DATA(&req);
	set_nl_attr(na, IPUDP_A_CMD_SPEC, &cmd_spec, sizeof(int));
	req.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);

	/* second attribute - viface params */
	na = (struct nlattr *) GENLMSG_NLA_NEXT(na);
	set_nl_attr(na, IPUDP_A_VIFACE_PARAMS, v, sizeof(ipudp_viface_params));
	req.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);

	/* third attribute - tun params */
	na = (struct nlattr *) GENLMSG_NLA_NEXT(na);
	set_nl_attr(na, IPUDP_A_TUN_PARAMS, p, sizeof(ipudp_tun_params));
	req.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);

	/* send nl message */
	if (sendto_fd(nl_sd, (char *) &req, req.n.nlmsg_len) < 0)  {
		printf("ipudp_genl: error sending genl message\n");
		return -1;
	}

	if ((receive_response()) < 0) {
		printf("receive_response error!\n");
		return -1;
	}
	
	parse_nl_attrs();

	if ((ret = *(int *)get_nl_data(IPUDP_A_RET_CODE)))
		__print_ipudp_error(ret);
	else {
		//v = (ipudp_viface_params *) get_nl_data(IPUDP_A_TUN_PARAMS);
		t = (ipudp_tun_params *) get_nl_data(IPUDP_A_TUN_PARAMS);
		printf("tunnel %d successfully added\n", t->tid);
		p->tid = t->tid;
	}

	return ret;
}

int 
do_cmd_add_rule(ipudp_viface_params *v, void *rule, int size) {
	struct nlattr *na;
	//struct sockaddr_nl nladdr;
	int ret;
	ipudp_nl_cmd_spec cmd_spec = CMD_S_RULE;
	
	/* fill the header */
	req.n.nlmsg_len 	= NLMSG_LENGTH(GENL_HDRLEN);
	req.n.nlmsg_type 	= ipudp_fam_id;
	req.n.nlmsg_flags 	= NLM_F_REQUEST;
	req.n.nlmsg_seq 	= 0;
	req.n.nlmsg_pid 	= getpid();
	req.g.cmd 			= IPUDP_C_ADD;


	/* first attribute - cmd specification: RULE */
	na = (struct nlattr *) GENLMSG_DATA(&req);
	set_nl_attr(na, IPUDP_A_CMD_SPEC, &cmd_spec, sizeof(int));
	req.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);

	/* second attribute - viface params */
	na = (struct nlattr *) GENLMSG_NLA_NEXT(na);
	set_nl_attr(na, IPUDP_A_VIFACE_PARAMS, v, sizeof(ipudp_viface_params));
	req.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);

	/* third attribute - rule params */
	na = (struct nlattr *) GENLMSG_NLA_NEXT(na);
	set_nl_attr(na, IPUDP_A_RULE_PARAMS, rule, size);
	req.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);

	/* send nl message */
	if (sendto_fd(nl_sd, (char *) &req, req.n.nlmsg_len) < 0)  {
		printf("ipudp_genl: error sending genl message\n");
		return -1;
	}

	if ((receive_response()) < 0) {
		printf("receive_response error!\n");
		return -1;
	}
	
	parse_nl_attrs();

	if ((ret = *(int *)get_nl_data(IPUDP_A_RET_CODE)))	
		__print_ipudp_error(ret);
	else
		printf("rule successfully added\n");

	return ret;
}
