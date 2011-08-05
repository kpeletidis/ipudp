#include "ipudp_server.h"

#define CMD_STR_LEN 4
#define CMD_GET_VADDR "0001" //SSL - req: "0001" -> resp: "ret_code:vaddr"
#define CMD_REQUEST_TUNNEL "0002" // SSL - 
#define CMD_CREATE_TUNNEL "0003" // UDP - 
#define CMD_KEEP_ALIVE "0004" // UDP -
#define CMD_SHUTDOWN "0020"	// SSL - 

#define RET_OK "00"
#define RET_ERR "11"

static int
__is_cmd_equal(char *line, char *cmd) {
	return (!strncmp(line, cmd, CMD_STR_LEN) ? 1 : 0);
}

static int
send_resp(char *msg, struct client *c, struct sockaddr *from, int seq) {

	if (c) //SSL
		return ssl_write_n(c->ssl, (unsigned char *)msg, strlen(msg));
	else if (from) //UDP
		return -1;
	else
		return 1;
}

static void
handle_get_vaddr(struct client *c, struct server_data *s) {
	__u32 ret_addr = s->first_addr  + 1;
	struct vaddr *a = NULL, *new;
	char resp[32]= { 0 };
	struct list_head *pos = NULL;
	char *ret_code = RET_OK;

	if (verbose) printf("handling get_vaddr\n");

	/* get first available address */
	list_for_each_entry(a, &s->v_addrs, list) {
		if (a->addr != ret_addr)
			break;	
		ret_addr ++;
	}

	if (ret_addr > DEFAULT_LAST_ADDR) {
		ret_addr = 0; //error - couldn't allocate a vaddr
		ret_code = RET_ERR;
		goto send_resp;
	}
	new = malloc(sizeof(struct vaddr));
	new->addr = ret_addr;
	new->client = c;

	/* keep the list ordered */
	if (list_empty(&s->v_addrs))
		pos = &s->v_addrs;
	else
		pos = &a->list;
	
	list_add_tail(&new->list, pos);

#ifdef DBG
	char tmp[32];

	printf("addr list: \n");
	list_for_each_entry(a, &s->v_addrs, list) { 
		printf("addr: %s\n", inet_ntop(AF_INET, &a->addr, tmp, 32));
	}
#endif

send_resp:
	sprintf(resp, "%s:%d\n", ret_code, ret_addr);	

	if (send_resp(resp, c, NULL, 0) < 0)
		client_shutdown(c, s);
}

void
handle_unknown_cmd(struct client *c, struct sockaddr *from, int seq){
	char resp[64];	
	sprintf(resp, "%s:%s\n", RET_ERR, "unknown message");	
	send_resp(resp, c, from, seq);
}

void 
proto_handle_msg(char *buf, int len, struct client *c, struct server_data *s) {

	if (__is_cmd_equal(buf, CMD_GET_VADDR))
		handle_get_vaddr(c, s);	
	//else if ;
	else
		handle_unknown_cmd(c, NULL, 0);
}

/* handle msgs received from the udp socket */
void
proto_handle_udp_msg(char *buf, int len, struct sockaddr from, int fromlen/*useless XXX*/, struct server_data *s) {
	int seq = 0;

	if (__is_cmd_equal(buf, CMD_CREATE_TUNNEL))
		;//TODO
	else if (__is_cmd_equal(buf, CMD_KEEP_ALIVE))
		;//TODO
	else
		handle_unknown_cmd(NULL, &from, seq);

	return;
}
