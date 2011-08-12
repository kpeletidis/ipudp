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

	print_log("Checking for ipudp module...");
	if (!__is_ipudp_mod_loaded()) {
		print_log("not found!\n");
		memset(c_data.viface,0,VIFACE_STR_LEN);
		return -1;
	}
	print_log("found!\n");

	if (ipudp_genl_client_init() < 0) {
        print_log("ipudp_genl_client_init error\n");
        return -1;
    }

	return 0;
}

int 
ipudp_conf_fini(void) {
	if (strlen(c_data.viface) == 0)
		return 0;
	
	if (ipudp_conf_cmd(IPUDP_CONF_DEL_VIFACE, NULL) < 0)
		print_log("warning: couldn't remove viface\n");

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

			print_log("Configuring viface address...");
			sprintf(cmd_str, "ifconfig %s %s", c_data.viface, addr);
			if (system(cmd_str) == 0) {
				print_log("done!\n");
			}
			else {
				print_log("error!\n");
				ret = -1;
			}
			break;
		}

		case IPUDP_CONF_ADD_VIFACE: {
			char *viface = (char *)args;		
			ipudp_viface_params prms;	

			memset(&prms, 0, sizeof(ipudp_viface_params));
			if (verbose) printf("adding %s interface...", viface);
			memcpy(prms.name, viface, MAX_IPUDP_DEV_NAME_LEN);
			if (do_cmd_add_viface(&prms) == 0) {
				if (verbose) printf("done!\n");
				strcat(c_data.viface, viface);
			}
			else {
				if (verbose) printf("error!\n");
				memset(c_data.viface, 0, VIFACE_STR_LEN);
				ret = -1;
			}
			break;
		}
		case IPUDP_CONF_DEL_VIFACE: {
			ipudp_viface_params prms;	

			memset(&prms, 0, sizeof(ipudp_viface_params));
			if (verbose) printf("removing %s interface...", c_data.viface);
			memcpy(prms.name, c_data.viface, MAX_IPUDP_DEV_NAME_LEN);
			if (do_cmd_del_viface(&prms) == 0) {
				if (verbose) printf("done!\n");
			}
			else {
				if (verbose) printf("error!\n");
				ret = -1;
			}
			break;
		}
		case IPUDP_CONF_ADD_TUN: {
			struct tunnel *t = (struct tunnel *)args;
			ipudp_tun_params tun; 
			ipudp_viface_params viface;

			print_log("Adding tunnel...");

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

    printf("Installing tunnelì: src %s dst %s lport %d rport %d viface %s\n",
        inet_ntop(AF_INET, &t->local_addr.sin_addr, laddr, 32),
        inet_ntop(AF_INET, &t->server_addr.sin_addr, raddr, 32),
        ntohs(t->local_addr.sin_port), ntohs(t->server_addr.sin_port),c_data.viface);
#endif
            ret = do_cmd_add_tun(&viface, &tun);
            t->tid = tun.tid;

			if (ret == 0) {
				print_log("done!\n");
			}
			else {
				print_log("error!\n");
				ret = -1;
			}

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

			ret = do_cmd_del_tun(&viface, &tun);


		}

		default:
			ret = -1;
	}	
	return ret;
}
