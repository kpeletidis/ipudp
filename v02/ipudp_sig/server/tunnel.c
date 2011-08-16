#include "ipudp_server.h"

void __set_token_string(char *buf) {
	unsigned char tmp[TOKEN_LEN];
	int i;

	RAND_bytes(tmp, TOKEN_LEN);		
	for (i=0; i<TOKEN_LEN; i++) {
		sprintf(buf+2*i,"%02x",tmp[i]);
	}
}

void tunnel_close(struct server_data *s/*XXX useless*/, struct tunnel *t) {
	void *arg[2];
	arg[0] = s;
	arg[1] = t;

	if (verbose) printf("closing tunnel %d\n", t->tid);
	
	if (t->tid)
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

	memcpy(&t->addr, from, sizeof(struct sockaddr_in));

	arg[0] = s;
	arg[1] = t;

	return ipudp_conf_cmd(IPUDP_CONF_ADD_TUNNEL, arg);
}

int tunnel_set_rule(struct server_data *s, struct client *c, struct tunnel *t){
	void *arg[3];

	arg[0] = s;
	arg[1] = c;
	arg[2] = t;

	return ipudp_conf_cmd(IPUDP_CONF_ADD_RULE, arg);
}

void tunnel_check_keepalive(void *a, void *user_ctx /*ignored*/) {
	struct server_data *s = (struct server_data *)a;
	struct timeval now, res;
	struct client *c;
	struct tunnel *t,*p;

	gettimeofday(&now, NULL);

	if (verbose) printf("checking keepalive status...\n");

	list_for_each_entry(c, &s->clients, list) {
printf("client %d\n", c->cfd);
		list_for_each_entry_safe(t, p, &c->tunnels, list) {
			if (t->state == TUN_STATE_WAIT_CREATE)
				continue;
			timersub(&now, &t->last_ka, &res);
			if (res.tv_sec > TUNNEL_MAX_IDLE_TIME)  {
				if (verbose) printf("tunnel %d expired\n", t->tid);
				tunnel_close(s, t);
			}
			else {
				if (verbose) printf("tunnel %d ok\n", t->tid);
			}
		}
	}

	//re-schedule the cb
	if ((mainloop_register_timeout(KEEPALIVE_CHECK_TO, 0, tunnel_check_keepalive, (void *)s, NULL) < 0)) {
		printf("error: mainloop_register_timeout error\n");
		server_shutdown(s);
	}
	
	if (verbose) printf("done\n");
}
