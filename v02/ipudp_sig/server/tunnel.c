#include "ipudp_server.h"

void __set_token_string(char *buf) {
	unsigned char tmp[TOKEN_LEN];
	int i;

	RAND_bytes(tmp, TOKEN_LEN);		
	for (i=0; i<TOKEN_LEN; i++) {
		sprintf(buf+2*i,"%02x",tmp[i]);
	}
}

void tunnel_close(struct server_data *s, struct tunnel *t) {
	void *arg[2];
	arg[0] = s;
	arg[1] = t;

	if (verbose) printf("closing tunnel %d\n", t->tid);

	ipudp_conf_cmd(IPUDP_CONF_DEL_TUNNEL, arg);
	list_del(&t->list);
	free(t);
}

void tunnel_close_all(struct server_data *s, struct client *c) {
	struct tunnel *t, *tt;

	list_for_each_entry_safe(t,tt, &c->tunnels, list) {
		tunnel_close(s,t);
	}

}

void tunnel_set_token(char *buf) {
	__set_token_string(buf);
} 

int tunnel_configure(struct server_data *s, struct client *c, struct tunnel *t, struct sockaddr_in *from){
	void *arg[2];
	int ret;

	memcpy(&t->addr, from, sizeof(struct sockaddr_in));

	arg[0] = s;
	arg[1] = t;

	ret = ipudp_conf_cmd(IPUDP_CONF_ADD_TUNNEL, arg);

	return ret;
}
