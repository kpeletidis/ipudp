#include "ipudp_client.h"

#define CMD_STR_LEN 4
#define CMD_GET_VADDR "0001" //SSL - req: "0001" -> resp: "ret_code:vaddr"
#define CMD_REQUEST_TUNNEL "0002" // SSL - req: "0002:token_client" --> resp: "ret_code:token_server"
#define CMD_CREATE_TUNNEL "0003" // UDP - req: "0003:seq:token_server" --> resp: "ret_code:seq:token_client"
#define CMD_SHUTDOWN "0020"	// SSL - 
//keepalive starts with escape sequence 0xffffffff

#define RET_OK "00"
#define RET_ERR "11"

#define UDP_TIMEOUT 3

static __u32 seq_num = 0;

static int __get_seq_num() {
	if (seq_num == 0xffffffff)
		seq_num = 0;
	else
		seq_num++;

	return seq_num;
}

int 
timeout_recvfrom(int sock, void *data, int l, int to) {
	fd_set socks;
	struct timeval t;
	int i;
	
	FD_ZERO(&socks);
	FD_SET(sock, &socks);
	t.tv_sec = to;
	t.tv_usec = 0;

	i = select(sock + 1, &socks, NULL, NULL, &t);
	switch(i) {
		case 0:
			print_log("udp recvfrom timeout expired\n");
			return -2;
		case -1:
			return -1;
		default:
			return recvfrom(sock, data, l, 0, NULL, NULL);
	}
}

//check if return code is ok|error and move the pointer p on the xent argument
static int __is_retcode_ok(char *buf, char **p) {
	int ret = 0;
	char *pos;

	/* integrity check */
	if (!(pos = strstr(buf, ":"))) {
		*p = NULL;
	}

	*p = pos + 1;

	if (!strncmp(buf, RET_OK, 2)) {
		ret = 1;
	}
	else if (!strncmp(buf, RET_ERR, 2))
		;
	else {
		*p = NULL;
		return ret;
	}
		
	return ret;
}

//return p = address of the next ":"
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

static int send_keepalive(char *buf, struct tunnel *t, int l) {
		return sendto(t->fd, (void *)buf, l, 0,
			(struct sockaddr *)&c_data.udp_server, sizeof(struct sockaddr_in));
}

static int 
send_req(char *buf, struct tunnel *t) {
	if (!t) 
		return ssl_write_n(ssl, (unsigned char *)buf, strlen(buf));	
	else {
		return sendto(t->fd, (void *)buf, strlen(buf), 0,
			(struct sockaddr *)&c_data.udp_server, sizeof(struct sockaddr_in));
	}
}

int
do_reqtun(char *dev) {
	char req[1024] = {0}, buf[1024] = {0}, tmp[256] = {0};
	int l = 0, try = 0;
	__u32 seq, ret_seq;
	char *p = NULL;
	struct tunnel *tun;

	/* init tunnel data */
	if (!(tun = tunnel_init(dev))) {
		print_log("do_reqtun: tunnel_init error\n");
		return -1;
	}
	sprintf(buf, "%s:%s\n", CMD_REQUEST_TUNNEL, tun->token_client);

	if (send_req(buf, NULL) < 0){
		print_log("do_reqtun: send_req error\n");
		goto free_tun;
	}
	memset(buf, 0, 1024);

	/* get response */
	if (ssl_readline(ssl, (void *)buf, 256, &l) < 0)
		goto free_tun;

	//cancel \n char
	buf[l]=0;

#ifdef DBG
	printf("do_reqtun: getline %d bytes - resp %s\n", l, buf);
#endif

	/* parse resp */
	if (__is_retcode_ok(buf, &p)) {
		memset(tun->token_server, 0, 2*TOKEN_LEN+1);
		memcpy(tun->token_server, p, 2*TOKEN_LEN);
		sprintf(tmp,"do_reqtun: starting tunnel establishment token: %s - %s\n",tun->token_server, p);
		print_log(tmp);
	}
	else if(p) {
		sprintf(tmp, "do_reqtun: tunnel request error. reason: %s\n", p);
		print_log(tmp);
		goto free_tun;
	}
	else {	
		print_log("do_reqtun: tunnel request response error. Bad format\n");
		goto free_tun;
	}

	/* send udp request with sec:token */
	seq = __get_seq_num();
	
	memset(req, 0, 1024);
	sprintf(req,"%s:%u:%s\n", CMD_CREATE_TUNNEL, seq, tun->token_server);
    
send_again:
	try ++;
#ifdef DBG
	printf("do_reqtun: try %d\n", try);
#endif

	if (send_req(req, tun) < 0){
		print_log("do_reqtun: send_req error\n");
		return -1;
	}

	/* get resp */
	memset(buf, 0, 1024);
	switch (l = timeout_recvfrom(tun->fd, buf, 1024, UDP_TIMEOUT)) {
		case -1:
			print_log("do_reqtun: recvfrom_error");
			goto free_tun;
		case -2:
			if (try > 3) 
				goto free_tun;
			else
				goto send_again;
		default:
			break;
	}

#ifdef DBG
	printf("do_reqtun: recvfrom %d bytes - resp %s\n", l, buf);
#endif
	/* parse resp */
	if (__is_retcode_ok(buf, &p)) {
		char arg[32] = { 0 };

		//get sequence number
		__get_next_arg(p, &p, arg, 32);

		if ((ret_seq = (__u32)atoi(arg)) == 0) 
			goto bad_format;
		if (ret_seq != seq) //silently discard and receive again
			goto send_again;

		memset(arg, 0, 32);

#ifdef DBG
	printf("do_reqtun: ret_seq %d token %s\n", ret_seq, p);
#endif

		//get token - now p points to the last arg
		if (!strcmp((const char *)p, (const char *)tun->token_client)) {
			goto bad_format;
		}

		print_log("do_reqtun: tunnel succesfully registered at the server. local configuration..\n");
	}
	else if(p) {
		sprintf(tmp, "do_reqtun: tunnel create error. reason: %s\n", p);
		print_log(tmp);
		goto free_tun;
	}
	else {
bad_format:
		print_log("do_reqtun: tunnel create response error. Bad format\n");
		goto free_tun;
	}

	if (tunnel_add(tun) < 0) {
		print_log("do_reqtun: couldn't add tunnel to module\n");
		goto free_tun;
	}
	return 0;

free_tun:
	tunnel_close(tun);
	return -1;
}

static int
__is_keepalive(char *buf) {
    __u32 escape = 0xffffffff;

    if (!memcmp(buf,&escape,4)) 
        return 1;
    else
        return 0;
}

int
do_keepalive(struct tunnel *tun) {
	char buf[256] = {0}, resp[256] = {0}, tmp[32] = {0};
	int l = 0, try = 0;
	char *p = NULL;
	__u32 seq = __get_seq_num();
	int ret_seq;

	/* send udp request with code:sec */
	seq = __get_seq_num();
	
	memset(buf, 0, 256);
	sprintf(buf+4,"%u\n", seq);
	buf[0] = 0xff;
	buf[1] = 0xff;
	buf[2] = 0xff;
	buf[3] = 0xff;

send_again:
	try ++;
#ifdef DBG
	printf("do_keepalive: try %d\n", try);
#endif

	if (send_keepalive(buf, tun, strlen(buf+4) + 4) < 0){
		print_log("do_keepalive: send_req error\n");
		goto ret_err;
	}

recv_again:
	/* get resp */
	memset(resp, 0, 256);
	switch (l = timeout_recvfrom(tun->fd, resp, 256, UDP_TIMEOUT)) {
		case -1:
			print_log("do_keepalive: recvfrom_error");
			goto ret_err;
		case -2:
			if (try > 3) 
				goto ret_err;
			else
				goto send_again;
		default:
			break;
	}

	/* parse resp */
	if ( __is_keepalive(resp) && __is_retcode_ok(resp + 4, &p)) {
		//get sequence number
		if ((ret_seq = (__u32)atoi(p)) == 0) 
			goto bad_format;
		if ((ret_seq != seq)){ //silently discard and receive again
			goto recv_again;
	}
		print_log("do_keepalive: ok\n");
	}
	else if(p) {
		sprintf(tmp, "do_keepalive: error, reason: %s\n", p);
		print_log(tmp);
		goto ret_err;
	}
	else {
bad_format:
		print_log("do_keepalive: keepalive response error. Bad format\n");
		goto ret_err;
	}
	return 0;

ret_err:
	return -1;
}


int
do_getvaddr(char *viface) {
	char buf[256] = {0}, tmp[32] = {0};
	int l = 0;
	char *p = NULL;

	sprintf(buf, "%s\n", CMD_GET_VADDR);

	if (send_req(buf, NULL) < 0){
		print_log("do_getvaddr: send_req error\n");
		return -1;
	}

	memset(buf, 0, 256);

	/* get response */
	if (ssl_readline(ssl, (void *)buf, 256, &l) < 0)
		return -1;

	//cancel \n char
	buf[l]=0;

#ifdef DBG
	printf("do_getvaddr: getline %d bytes - resp %s\n", l, buf);
#endif

	if (__is_retcode_ok(buf, &p)) {
		c_data.vaddr = htonl((__u32)atoi(p));
		if (verbose) printf("do_getvaddr: assigned vaddr: %s\n", 
						inet_ntop(AF_INET, &c_data.vaddr, tmp, 32));		
	}
	else if (p){
		if (verbose) printf("do_getvaddr: couldn't assign vaddr. Error reason: %s\n", p);	
		return -1;
	}
	else {	
		if (verbose) printf("do_getvaddr: couldn't assign vaddr. Bad format\n");
		return -1;
	}
	
	if (ipudp_conf_cmd(IPUDP_CONF_ADD_VIFACE, (void *)viface) < 0)
		return -1;

	if (ipudp_conf_cmd(IPUDP_CONF_SET_VADDR, NULL) < 0)
		return -1;

	return 0;
}
