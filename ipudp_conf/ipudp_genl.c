
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

/* XXX TODO XXX use a function to init genl header */



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
		perror("Unable to create netlink socket");
		return -1;
	}

	memset(&local, 0, sizeof(local));
	local.nl_family = AF_NETLINK;
	local.nl_groups = groups;
	local.nl_pid 	= getpid();

	if (bind(fd, (struct sockaddr *) &local, sizeof(local)) < 0){
		close(fd);
		perror("Unable to bind netlink socket");
		return -1;
	}
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
do_cmd_module_test(void){
	struct nlattr *na;
	//struct sockaddr_nl nladdr;
	char * echo_str = "Hi from user space\n"; 
	int err = 0;
	char *s;
	
	/* fill the header */
	req.n.nlmsg_len 	= NLMSG_LENGTH(GENL_HDRLEN);
	req.n.nlmsg_type 	= ipudp_fam_id;
	req.n.nlmsg_flags 	= NLM_F_REQUEST;
	req.n.nlmsg_seq 	= 0;
	req.n.nlmsg_pid 	= getpid();
	req.g.cmd 		= IPUDP_C_MODULE_TEST;


	/* first attribute - msg type */
	na = (struct nlattr *) GENLMSG_DATA(&req);
	set_nl_attr(na, IPUDP_A_STRING, echo_str, 
					strlen(echo_str));
	req.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);

	
	/* send nl message */
	if (sendto_fd(nl_sd, (char *) &req, req.n.nlmsg_len) < 0)  {
		printf("ipudp_genl: error sending genl message\n");
		return -1;
	}

	if ((err = receive_response()) < 0){ 
		printf("receive_response error!\n");
		return err;
	}
	
	parse_nl_attrs();
	
	err = *(int*)get_nl_data(IPUDP_A_RET_CODE);	
	s = (char *) get_nl_data(IPUDP_A_STRING);

	return err;
}

int 
do_cmd_add_viface(ipudp_viface_params *p){
	struct nlattr *na;
	//struct sockaddr_nl nladdr;
	int ret;
	ipudp_nl_cmd_spec cmd_spec = CMD_S_VIFACE;
	char *error_desc = NULL;
	
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
	if ((ret = *(int *)get_nl_data(IPUDP_A_RET_CODE))) {	
		printf("do_cmd_add_viface: error code: %d\n",ret);
		
		if ((error_desc = (char *)  get_nl_data(IPUDP_A_ERROR_DESC)))
			printf("%s\n",error_desc);
	}
	else {
		p = (ipudp_viface_params *) get_nl_data(IPUDP_A_VIFACE_PARAMS);
		printf("Viface %s successfully added\n", p->name);
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
		printf("do_cmd_tun_viface: error code: %d\n",ret);
	else {
		//p = (ipudp_viface_params *) get_nl_data(IPUDP_A_TUN_PARAMS);
		printf("tunnel %d for viface %s successfully removed\n", p->tid, q->name);
	}

	return 0;
}


int 
do_cmd_del_viface(ipudp_viface_params *p){
	struct nlattr *na;
	//struct sockaddr_nl nladdr;
	int ret;
	ipudp_nl_cmd_spec cmd_spec = CMD_S_VIFACE;
	char *error_desc = NULL;
	
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
	
	if ((ret = *(int *)get_nl_data(IPUDP_A_RET_CODE))) {	
		printf("do_cmd_del_viface: error code: %d\n",ret);
	
		//XXX	
		if ((error_desc = (char *)  get_nl_data(IPUDP_A_ERROR_DESC)))
			printf("%s\n",error_desc);
	}
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

		//TODO extend it
		
		default:
			printf("Unknown viface mode\n");
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
			printf("Unknown af_out\n");
			return;
	}
	
	printf("\tinterface %s, outer header %s, encapsulation mode %s\n",p->name, af, mode);

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
			inet_ntop(AF_INET, &(data->u.v6p.src), ip_src, 64);
		inet_ntop(AF_INET, &(data->u.v6p.dest), ip_dest, 64);
	}
	else {
		printf("unknown outer af family\n");
		return;
	}

	if (data->dev_idx) {
		if (get_iface_name_by_idx(data->dev_idx, ifname) < 0) {
			sprintf(temp,"underlying device index %d", data->dev_idx);
			printf("warning: error getting iface name from index. Are you root?\n");
		}
		else 	
			sprintf(temp,"underlying device %s", ifname);
	}
	else
		sprintf(temp,"source IP address %s", ip_src);

	printf("\ttunnel %d, %s, destination IP address %s, source UDP port %d, destination UDP port %d, mark %d\n",
			data->tid, temp, ip_dest, ntohs(data->srcport), ntohs(data->destport), data->mark);

	return;
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
		case CMD_S_TSA:
			/*TODO*/
			break;
		case CMD_S_RULE:
			/*TODO*/
			break;
		default: //can't happen...
			printf("Unknown cmd_type %d\n",cmd_spec);
			break;
	}
}

//this function is realyl really ugly... TODO
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
			printf("do_cmd_list: error code %d\n", ret_code);
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
	if (cmd_spec != CMD_S_VIFACE) 
		printf("list type %d for virtual interface %s, n_intems: %d\n", cmd_spec, 
				list_params->dev_name, list_params->n_items);	
	else 
		printf("virtual interface list, n_intems: %d\n", list_params->n_items);	
		
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
	
	//TODO iface idx from name
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
	char *error_desc = NULL;
	
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
	/* parse the response: 
	in this case we expect a msg without attributes (OK)
	or a message with IPUDP_A_ERROR_DESC (an error occurred)*/
	if ((ret = *(int *)get_nl_data(IPUDP_A_RET_CODE))) {	
		printf("do_cmd_add_tun: error code: %d\n",ret);
		
		if ((error_desc = (char *)  get_nl_data(IPUDP_A_ERROR_DESC)))
			printf("%s\n",error_desc);
	}
	else {
		v = (ipudp_viface_params *) get_nl_data(IPUDP_A_TUN_PARAMS);
		printf("Tunnel successfully added\n");
	}


	return ret;
}

