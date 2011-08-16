#include "ipudp_client.h"
#include <ipudp_conf.h>

#define IPUDP_MOD_PATH "/home/marlon/Src/ipudp/v02/ipudp_mod/ipudp.ko" //XXX into a conf file
#define IPUDP_CONF_PATH "/home/marlon/Src/ipudp/v02/ipudp_conf/ipudp_conf" //XXX into a conf file

static 
int __is_ipudp_mod_loaded() {
	char *cmd = "lsmod | egrep \"\\<ipudp\\>\" > /dev/null";	
	
	if (system(cmd) == 0)
		return 1;
	else
		return 0;
}

int 
ipudp_conf_init(void) {

	if (!__is_ipudp_mod_loaded()) {
		print_log("error: ipudp module not loaded", LOG_LEVEL_IMPORTANT);
		memset(c_data.viface,0,VIFACE_STR_LEN);
		return -1;
	}

	if (ipudp_genl_client_init() < 0) {
        print_log("error: ipudp_genl_client_init failed", LOG_LEVEL_IMPORTANT);
        return -1;
    }

	return 0;
}

int 
ipudp_conf_fini(void) {
	if (strlen(c_data.viface) == 0)
		return 0;
	
	if (ipudp_conf_cmd(IPUDP_CONF_DEL_VIFACE, NULL) < 0)
		return -1;

	return 0;
}

int 
ipudp_conf_cmd(int cmd, void *args) {
	int ret = 0;
	char cmd_str[64];

	switch(cmd) {
		case IPUDP_CONF_SET_VADDR: {
			char addr[32] = { 0 };

			inet_ntop(AF_INET, &c_data.vaddr, addr, 32);

			sprintf(cmd_str, "ifconfig %s %s", c_data.viface, addr);
			if (system(cmd_str) == 0) 
				print_log("virtual interface IP address configured", LOG_LEVEL_IMPORTANT);
			
			else {
				print_log("error: virtual interface IP address configuration error", LOG_LEVEL_IMPORTANT);
				ret = -1;
			}
			break;
		}

		case IPUDP_CONF_ADD_VIFACE: {
			char *viface = (char *)args;		
			ipudp_viface_params prms;	

			memset(&prms, 0, sizeof(ipudp_viface_params));
			memcpy(prms.name, viface, MAX_IPUDP_DEV_NAME_LEN);
			if (do_cmd_add_viface(&prms) == 0) {
				print_log("virtual interface added", LOG_LEVEL_NOTIFICATION);
				strcat(c_data.viface, viface);
			}
			else {
				print_log("error: couldn't add virtual interface", LOG_LEVEL_IMPORTANT);
				memset(c_data.viface, 0, VIFACE_STR_LEN);
				ret = -1;
			}
			break;
		}
		case IPUDP_CONF_DEL_VIFACE: {
			ipudp_viface_params prms;	

			memset(&prms, 0, sizeof(ipudp_viface_params));
			memcpy(prms.name, c_data.viface, MAX_IPUDP_DEV_NAME_LEN);
			if (do_cmd_del_viface(&prms) == 0) {
				print_log("virtual interface removed", LOG_LEVEL_NOTIFICATION);
			}
			else {
				print_log("error: couldn't remove virtual interface", LOG_LEVEL_IMPORTANT);
				ret = -1;
		}
			break;
		}
		case IPUDP_CONF_ADD_TUN: {
			struct tunnel *t = (struct tunnel *)args;
			ipudp_tun_params tun; 
			ipudp_viface_params viface;

            memset(&tun, 0, sizeof(tun));
            memset(&viface, 0, sizeof(viface));

            tun.af = IPV4;
            tun.u.v4p.src = t->local_addr.sin_addr.s_addr;
            tun.u.v4p.dest = t->server_addr.sin_addr.s_addr;
            tun.srcport = t->local_addr.sin_port;
            tun.destport = t->server_addr.sin_port;

            memcpy(viface.name, c_data.viface, MAX_IPUDP_DEV_NAME_LEN);
#ifdef DBG
	char laddr[32] = { 0 };
	char raddr[32] = { 0 };

    printf("Installing tunnel: src %s dst %s lport %d rport %d viface %s\n",
        inet_ntop(AF_INET, &t->local_addr.sin_addr, laddr, 32),
        inet_ntop(AF_INET, &t->server_addr.sin_addr, raddr, 32),
        ntohs(t->local_addr.sin_port), ntohs(t->server_addr.sin_port),c_data.viface);
#endif

			if (do_cmd_add_tun(&viface, &tun) == 0) {
				print_log("ipudp tunnel added", LOG_LEVEL_NOTIFICATION);
			}
			else {
				print_log("couldn't add ipudp tunnel", LOG_LEVEL_IMPORTANT);
				ret = -1;
			}

            t->tid = tun.tid;
			break;
		}

		case IPUDP_CONF_DEL_TUN: {
			ipudp_tun_params tun; 
			ipudp_viface_params viface;
			
			struct tunnel * t = (struct tunnel*)args;

			memset(&tun, 0, sizeof(tun));
			memset(&viface, 0, sizeof(viface));
			memcpy(viface.name, c_data.viface, MAX_IPUDP_DEV_NAME_LEN);
			tun.tid = t->tid;

			if (do_cmd_del_tun(&viface, &tun) == 0) {
				print_log("ipudp tunnel removed", LOG_LEVEL_NOTIFICATION);
			}
			else {
				print_log("couldn't add ipudp tunnel", LOG_LEVEL_IMPORTANT);
				ret = -1;
			}

			break;
		}

		default:
			ret = -1;
	}	
	return ret;
}
