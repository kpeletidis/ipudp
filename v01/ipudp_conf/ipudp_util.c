#include "ipudp_conf.h" 

#include <string.h>
#include <sys/ioctl.h>

#include <sys/socket.h>

int 
get_iface_idx_by_name(char * name) {
	struct ifreq ifr;
	int s;

	s = socket(PF_PACKET, SOCK_DGRAM,0);
	memset(&ifr, 0, sizeof(ifr));

	strncpy(ifr.ifr_name, name, IFNAMSIZ);

	if (ioctl(s, SIOCGIFINDEX, &ifr) < 0) {
		close(s);
		return -1;
	}

	return ifr.ifr_ifindex;
}

int 
get_iface_name_by_idx(int dev_idx, char *ifname) {
	struct ifreq ifr;
	int s;

	s = socket(PF_PACKET, SOCK_DGRAM,0);
	memset(&ifr, 0, sizeof(ifr));

	ifr.ifr_ifindex = dev_idx;

	if (ioctl(s, SIOCGIFNAME, &ifr) < 0) {
		close(s);
		return -1;
	}

	memcpy(ifname, ifr.ifr_name, IFNAMSIZ);
	return 0;
}

