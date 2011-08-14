#include "ipudp_server.h"
#include <ipudp_conf.h>

#define IPUDP_MOD_PATH "/home/marlon/Src/ipudp/v02/ipudp_mod/ipudp.ko" //XXX into a conf file
#define IPUDP_CONF_PATH "/home/marlon/Src/ipudp/v02/ipudp_conf/ipudp_conf" //XXX into a conf file

static 
int __is_ipudp_mod_loaded() {
	char *cmd = "lsmod | egrep \"\\<ipudp\\>\">/dev/null";	
	
	if (system(cmd) == 0)
		return 1;
	else
		return 0;
}


int 
ipudp_conf_init(struct server_data *s) {
	char cmd[64] = { 0 };
	char addr[32] = { 0 };
	ipudp_viface_params viface;	

	if (verbose) printf("checking for ipudp module...");
	if (!__is_ipudp_mod_loaded()) {
		if (verbose) printf("not found\n");
		memset(s->viface_name,0,VIFACE_STR_LEN);
		return -1;
	}
	if (verbose) printf("found\n");
	
	if (verbose) printf("initializing ipudp conf library...");
	if (ipudp_genl_client_init() < 0) {
		if (verbose) printf("ipudp_genl_client_init error\n");
		return -1;
	}
	if (verbose) printf("done\n");

	memset(&viface, 0, sizeof(ipudp_viface_params));
	if (verbose) printf("adding %s interface...", s->viface_name);
	memcpy(viface.name, s->viface_name, MAX_IPUDP_DEV_NAME_LEN);
	viface.mode = MODE_MULTI_V4; 
	if (do_cmd_add_viface(&viface) == 0) {
		if (verbose) printf("done!\n");
	}
	else {
		if (verbose) printf("error!\n");
		memset(s->viface_name, 0, VIFACE_STR_LEN);
		return -1;
	}

	{	
		__u32 tmp = htonl(s->first_addr);
		inet_ntop(AF_INET, &tmp, addr, 32);
	}

	if (verbose) printf("configuring address %s on %s interface...", addr, s->viface_name);

	sprintf(cmd, "ifconfig %s %s",s->viface_name, addr);
	if (system(cmd) == 0) {
		if (verbose) printf("done!\n");
	}
	else {
		if (verbose) printf("error!\n");
		return -1;
	}

	return 0;
}

int 
ipudp_conf_fini(struct server_data* s) {
	ipudp_viface_params viface;	

	if (strlen(s->viface_name) == 0) return 0;

	memset(&viface, 0, sizeof(ipudp_viface_params));
	if (verbose) printf("removing %s interface...", s->viface_name);
	memcpy(viface.name, s->viface_name, MAX_IPUDP_DEV_NAME_LEN);
	if (do_cmd_del_viface(&viface) == 0) {
		if (verbose) printf("done!\n");
	}
	else {
		if (verbose) printf("error!\n");
		memset(s->viface_name, 0, VIFACE_STR_LEN);
		return -1;
	}

	return 0;
}

int 
ipudp_conf_cmd(int cmd, void **args) {
	int ret = 0;

	switch(cmd) {
		case IPUDP_CONF_ADD_TUNNEL: {
			ipudp_tun_params tun; 
			ipudp_viface_params viface;
			
			struct server_data * s = (struct server_data*)args[0]; 
			struct tunnel * t = (struct tunnel*)args[1];

			memset(&tun, 0, sizeof(tun));
			memset(&viface, 0, sizeof(viface));

			tun.af = IPV4;
			tun.u.v4p.src = s->local_addr;
			tun.u.v4p.dest = t->addr.sin_addr.s_addr; 
			tun.srcport = s->tun_port;
			tun.destport = t->addr.sin_port;
			memcpy(viface.name, s->viface_name, MAX_IPUDP_DEV_NAME_LEN);
#ifdef DBG
	char a[32], b[32];
	printf("Installing tunnel: src %s dst %s lport %d rport %d viface %s\n",
		inet_ntop(AF_INET, &s->local_addr, a, 32),
		inet_ntop(AF_INET, &t->addr.sin_addr, b, 32),
		ntohs(s->tun_port), ntohs(t->addr.sin_port),s->viface_name
	);
#endif
			ret = do_cmd_add_tun(&viface, &tun);
printf("returned tid %d\n", tun.tid);
			t->tid = tun.tid;
			break;
		}

		case IPUDP_CONF_DEL_TUNNEL: {
			ipudp_tun_params tun; 
			ipudp_viface_params viface;
			
			struct server_data * s = (struct server_data*)args[0]; 
			struct tunnel * t = (struct tunnel*)args[1];

			memset(&tun, 0, sizeof(tun));
			memset(&viface, 0, sizeof(viface));
			memcpy(viface.name, s->viface_name, MAX_IPUDP_DEV_NAME_LEN);
			tun.tid = t->tid;

			ret = do_cmd_del_tun(&viface, &tun);

			break;
		}

		case IPUDP_CONF_ADD_RULE: {
			ipudp_rule_multi_v4 rule;
			ipudp_viface_params viface;

			struct server_data *s = args[0];
			struct client *c = args[1];
			struct tunnel *t = args[2];

			memset(&rule, 0, sizeof(rule));
			memset(&viface, 0, sizeof(viface));

			memcpy(viface.name, s->viface_name, MAX_IPUDP_DEV_NAME_LEN);
			rule.type = MODE_MULTI_V4;
			rule.tun_id = t->tid;
            rule.dest = c->v_addr;
#ifdef DBG
char tmp[32];

printf("inserting rule for tunnel %d dest %s viface %s\n", rule.tun_id, inet_ntop(AF_INET, &rule.dest, tmp, 32), viface.name);
#endif
			ret = do_cmd_add_rule(&viface, &rule, sizeof(rule));

			break;
		}

	}	
	return ret;
}
