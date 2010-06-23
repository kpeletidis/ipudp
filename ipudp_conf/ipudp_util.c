#include "ipudp_conf.h" 

#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>  

#include <sys/socket.h>

int 
get_iface_idx_by_name(char * name) {
	struct ifreq ifr;
	int s;

	s = socket(PF_PACKET, SOCK_DGRAM,0);
	memset(&ifr, 0, sizeof(ifr));

	strncpy(ifr.ifr_name, name, IFNAMSIZ);

	// get the ifindex for the adapter...
	if (ioctl(s, SIOCGIFINDEX, &ifr) < 0) {
		close(s);
		return -1;
	}

	return ifr.ifr_ifindex;
}

