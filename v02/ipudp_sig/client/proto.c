#include "ipudp_client.h"

#define CMD_STR_LEN 4
#define CMD_GET_VADDR "0001" //SSL - req: "0001" -> resp: "ret_code:vaddr"
#define CMD_REQUEST_TUNNEL "0002" // SSL - 
#define CMD_CREATE_TUNNEL "0003" // UDP - 
#define CMD_KEEP_ALIVE "0004" // UDP -
#define CMD_SHUTDOWN "0020"	// SSL - 

#define RET_OK "00"
#define RET_ERR "11"


enum {
	SSL_CHAN,
	UDP_CHAN
};

static int __is_retcode_ok(char *buf, char **p) {
	int ret = 0;
	char *pos;
	
	/* integrity check */
	if (!(pos = strstr(buf, ":")))
		*p = NULL;

	*p = pos + 1;

	if (!strncmp(buf, RET_OK, 2))
		ret = 1;
	else if (!strncmp(buf, RET_ERR, 2))
		;
	else {
		*p = NULL;
		return ret;
	}
		
	return ret;
}

static int 
send_req(char *buf, int chan) {
	if (chan == SSL_CHAN) 
		return ssl_write_n(ssl, (unsigned char *)buf, strlen(buf));
	
	else if (chan == UDP_CHAN){
		return -1;
	}
	else
		return -1;
}

int
do_getvaddr(char *viface) {
	char buf[256] = {0}, tmp[32] = {0};
	int l = 0;
	char *p = NULL;

	sprintf(buf, "%s\n", CMD_GET_VADDR);

	if (send_req(buf, SSL_CHAN) < 0){
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
		goto err;
	}
	else {	
		if (verbose) printf("do_getvaddr: couldn't assign vaddr. Bad format\n");
		goto err;
	}
	
	if (ipudp_conf_cmd(IPUDP_CONF_ADD_VIFACE, (void *)viface) < 0)
		goto err;
	strcat(c_data.viface, viface);

	if (ipudp_conf_cmd(IPUDP_CONF_SET_VADDR, (void *)&c_data.vaddr) < 0)
		goto err;

	return 0;

err:
	return -1;
}
