#include "ipudp_client.h"

#define IPUDP_MOD_PATH "/home/marlon/Src/ipudp/v02/ipudp_mod/ipudp.ko" //XXX into a conf file
#define IPUDP_CONF_PATH "/home/marlon/Src/ipudp/v02/ipudp_conf/ipudp_conf" //XXX into a conf file

int 
ipudp_conf_init(void) {
	
	return 0;
}

int 
ipudp_conf_fini(void) {
	
	return 0;
}

int 
ipudp_conf_cmd(int cmd, void *args) {
	int ret = 0;

	switch(cmd) {
		case IPUDP_CONF_SET_VADDR:
		break;

		case IPUDP_CONF_ADD_VIFACE:
		break;

		case IPUDP_CONF_DEL_VIFACE:
		break;

		default:
			ret = -1;
	}	
	return ret;
}
