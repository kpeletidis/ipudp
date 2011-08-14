#include "ipudp_server.h"

#define CMD_STR_LEN 4
#define CMD_GET_VADDR "0001" //SSL - req: "0001" -> resp: "ret_code:vaddr"
#define CMD_REQUEST_TUNNEL "0002" // SSL - req: "0002:token_client" --> resp: "ret_code:token_server"
#define CMD_CREATE_TUNNEL "0003" // UDP - req: "0003:seq:token_server" --> resp: "ret_code:seq:token_client"
#define CMD_KEEP_ALIVE "0004" // UDP - req: "XXXX:seq" --> resp: "ret_code:seq"
#define CMD_SHUTDOWN "0020"	// SSL - 

#define RET_OK "00"
#define RET_ERR "11"

static int
__is_cmd_equal(char *line, char *cmd) {
	return (!strncmp(line, cmd, CMD_STR_LEN) ? 1 : 0);
}

//p = address of the next ":"
int  __get_next_arg(char *buf, char **p, char *arg, int max_len) {
	int i = 0;
	char *pos = buf;
	char c = *pos;

	while(c != ':') {
		if (i == max_len)
			return -1;
		*(arg+i)=c;
		i++;
		c = *(buf+i);
		pos++;
	}

	*(arg+i)='\0';
	*p = pos+1;
	return 0;
}

static int
send_resp(char *msg, struct client *c, struct sockaddr_in *from, int sock, int seq) {

	if (c) //SSL
		return ssl_write_n(c->ssl, (unsigned char *)msg, strlen(msg));
	else if (from) { //UDP
		if (verbose) printf("sendto: %s",msg);
		return sendto(sock, msg, strlen(msg), 0, (struct sockaddr *)from, sizeof(struct sockaddr_in));
	}
	else
		return 1;
}

static void
handle_request_tunnel(char *buf, struct client *c, struct server_data *s) {
	struct tunnel *tun; 
	char resp[64]= { 0 };
	char *ret_code = RET_OK;
	char *reason;
	int blen = strlen(buf) +1, add = 1;
	char arg[blen];
	char *p;

	if (verbose) printf("handling request_tunnel\n");

	tun = (struct tunnel *)malloc(sizeof(struct tunnel));
	if (!tun) {
		ret_code = RET_ERR;
		reason = "memory error";
		goto send_resp;
	}

	memset(tun,0,sizeof(struct tunnel));	
	//first arg - cmd
	memset(arg,0,blen);
	if (__get_next_arg(buf, &p, arg, blen) < 0) {
		ret_code = RET_ERR;
		reason = "bad format";
		goto send_resp;
	}
	//second arg - token
	tunnel_set_token(tun->token_server);	
	memset(tun->token_client, 0, 2*TOKEN_LEN+1);
	memcpy(tun->token_client, p, 2*TOKEN_LEN);

send_resp:
	if (!memcmp(ret_code,RET_ERR,2)) {
		sprintf(resp, "%s:%s\n", ret_code, reason);	
		if (tun)
			free(tun);
		add = 0;
	}
	else
		sprintf(resp, "%s:%s\n", ret_code, tun->token_server);

	if (send_resp(resp, c, NULL, 0, 0) < 0) {
		add = 0;
		if (tun) 
			free(tun);
	}

	if (add) {
		tun->state = TUN_STATE_WAIT_CREATE;
		if (verbose) printf("tun request for client %d\n", c->cfd);
		list_add(&tun->list, &c->tunnels);
	}

	return;
}

static void
handle_create_tunnel(char *buf, struct server_data *s, struct sockaddr_in *from) {
	struct client *c;
	struct tunnel *t;
	int blen = strlen(buf), seq, found = 0;
	char arg[blen];
	char *p, *reason, *ret_code=RET_OK, *token, resp[128] = {0};
	struct timeval now;

	//UDP - req: "0003:seq:token_server" --> resp: "ret_code:seq:token_client"
	if (verbose) printf("handling create tunnel\n");

	//first arg - cmd - just format verification
	memset(arg,0,blen);
	if (__get_next_arg(buf, &p, arg, blen) < 0) {
		ret_code = RET_ERR;
		reason = "bad format";
		goto send_err;
	}
	//second arg - seq number
	memset(arg,0,blen);
	if ((__get_next_arg(p, &p, arg, blen) < 0) || (!(seq = (__u32)atoi(arg)))) {
		ret_code = RET_ERR;
		reason = "bad format";
		goto send_err;
	}

	//third arg - token
	token = p;

	list_for_each_entry(c, &s->clients, list) {
		list_for_each_entry(t, &c->tunnels, list) {
			if (t->state == TUN_STATE_WAIT_CREATE) {
				if (!strcmp(t->token_server, token)) {
					found = 1;
					break;
				}
			}
		}
		if (found)
			break;
	}
		
	if (!found){
		ret_code = RET_ERR;
		reason = "no pending request";
		goto send_err;
	}

	if (tunnel_configure(s, c, t, from) != 0) {
		tunnel_close(s, t);
		ret_code = RET_ERR;
		reason = "tunnel configuration error";
		goto send_err;
	}

	if (tunnel_set_rule(s, c, t) != 0) {
		tunnel_close(s, t);
		ret_code = RET_ERR;
		reason = "tunnel rule configuration error";
		goto send_err;
	}

	gettimeofday(&now, NULL);
	memcpy(&t->last_ka, &now, sizeof(now));

	sprintf(resp, "%s:%02d:%s\n", ret_code, seq, t->token_client);
	if (send_resp(resp, NULL, from, s->tunfd, seq) < 0) {
		tunnel_close(s, t);
		return;
	}

	t->state = TUN_STATE_ESTABLISHED;

printf("\ntunnel %d inserted\n", t->tid);
	return;

send_err:
	sprintf(resp, "%s:%d:%s\n", ret_code, seq, reason);	
	send_resp(resp, NULL, from, s->tunfd, seq);

	return;
}

static int
__is_keepalive(char *buf) {
	__u32 escape = 0xffffffff;

	if (!memcmp(buf,&escape,4))
		return 1;
	else
		return 0;		
}


static void
handle_keep_alive(char *buf, int len, struct server_data *s, struct sockaddr_in *from) {	
	char *p = buf + 4;
	char resp[64] = {0}, *reason;
	struct client *c;
	struct tunnel *t;
	int found = 0, seq;
	char *ret_code = RET_OK;
	struct timeval now;

	//escape sequence for keepalive
	resp[0]= 0xff;
	resp[1]= 0xff;
	resp[2]= 0xff;
	resp[3]= 0xff;

	if (verbose) printf("handling keepalive\n");
	//seq
	if (!(seq=atoi(p)) || (len > 32)) {
		ret_code = RET_ERR;
		reason = "bad format";
		goto send_err;
	}

	//TODO use a tunnel hashtable indexed by the sockaddr
	list_for_each_entry(c, &s->clients, list) {
		list_for_each_entry(t, &c->tunnels, list) {
			if (!memcmp(&t->addr, from, sizeof(struct sockaddr_in))) {
				found = 1;
				break;
			}
		}
		if (found)
			break;
	}
		
	if (!found){
		ret_code = RET_ERR;
		reason = "no active tunnel";
		goto send_err;
	}


	sprintf(resp+4, "%s:%u\n", ret_code, seq);
	sendto(s->tunfd, resp, strlen(resp+4)+4, 0,
            (struct sockaddr *)&t->addr, sizeof(struct sockaddr_in));
	
	gettimeofday(&now, NULL);
	memcpy(&t->last_ka, &now, sizeof(now));

	return;
send_err:
	sprintf(resp+4, "%s:%02u:%s\n", ret_code, seq, reason);	

	sendto(s->tunfd, resp, strlen(resp+4)+4, 0,
            (struct sockaddr *)&t->addr, sizeof(struct sockaddr_in));
	return;
}


static void
handle_get_vaddr(char *buf, struct client *c, struct server_data *s) {
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

	c->v_addr = htonl(ret_addr);
#if 0
#ifdef DBG
	char tmp[32];

	printf("addr list: \n");
	list_for_each_entry(a, &s->v_addrs, list) { 
		printf("addr: %s\n", inet_ntop(AF_INET, &a->addr, tmp, 32));
	}
#endif
#endif

send_resp:
	sprintf(resp, "%s:%d\n", ret_code, ret_addr);	

	if (send_resp(resp, c, NULL, 0, 0) < 0)
		client_shutdown(c, s);
}

void
handle_unknown_cmd(struct server_data *s, struct client *c, struct sockaddr_in *from){
	char resp[64];
	int seq = 0;

	sprintf(resp, "%s:%s\n", RET_ERR, "unknown message");	
	send_resp(resp, c, from, s->tunfd, seq);
}

void
handle_bad_format(struct server_data *s, struct client *c, struct sockaddr_in *from){
	char resp[64];
	int seq = 0;

	sprintf(resp, "%s:%s\n", RET_ERR, "bad format");	
	send_resp(resp, c, from, s->tunfd, seq);
}

void 
proto_handle_msg(char *buf, int len, struct client *c, struct server_data *s) {

	if (__is_cmd_equal(buf, CMD_GET_VADDR))
		handle_get_vaddr(buf, c, s);
	else if (__is_cmd_equal(buf, CMD_REQUEST_TUNNEL))
		handle_request_tunnel(buf, c, s);
	else
		handle_unknown_cmd(s, c, NULL);
}

/* handle msgs received from the udp socket */
void
proto_handle_udp_msg(char *buf, int len, struct sockaddr_in *from, struct server_data *s) {
	char tmp[32] = { 0 };
	
#if DBG
	printf("received udp message from %s %d\n",
			inet_ntop(AF_INET, (void *)&from->sin_addr, tmp, 32) ,ntohs(from->sin_port));
#endif
	
	if (buf[len - 1] != '\n'){
		handle_bad_format(s, NULL, from);
		return;
	}
	else
		buf[len - 1] = '\0';
	//this ks thing should go into the module... for now let's keep it here...
	if (__is_keepalive(buf))
		handle_keep_alive(buf, len, s, (struct sockaddr_in *)from);
	else if (__is_cmd_equal(buf, CMD_CREATE_TUNNEL))
		handle_create_tunnel(buf, s, (struct sockaddr_in *)from);
	else
		handle_unknown_cmd(s, NULL, from);

	return;
}
