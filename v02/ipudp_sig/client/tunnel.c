#include "ipudp_client.h"

static int bindport  = 50300;

void __set_token_string(char *buf) {
	unsigned char tmp[TOKEN_LEN];
	int i;

	RAND_bytes(tmp, TOKEN_LEN);		
	for (i=0; i<TOKEN_LEN; i++) {
		sprintf(buf+2*i,"%02x",tmp[i]);
	}
}

struct tunnel *
tunnel_init(char *dev) {
	struct tunnel *tun = (struct tunnel *)malloc(sizeof(*tun));
	struct ifreq ifr;
	struct sockaddr_in addr;
	int s, i = 0;

	if (!tun)
		return NULL;

	memset(tun,0,sizeof(*tun));

  	if ((s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
		goto free_and_ret;
	/*	
	if (setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, dev, strlen(dev)) < 0)
		goto free_and_ret;
 	*/
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	if ( ioctl(s, SIOCGIFADDR, &ifr) < 0) {
		print_log("error: ioctl SIOCGIFADDR error\n");	
		goto free_and_ret;
	}
	while(1) {
	  	addr.sin_family = AF_INET;
  		addr.sin_port = htons(bindport);
		memcpy((void *)&addr.sin_addr, &((struct sockaddr_in *)(&ifr.ifr_addr))->sin_addr, 4);

  		if(bind(s, (struct sockaddr *)&addr, sizeof(addr)) == 0)	
			break;
		i++;
		if (bindport == 60000)
			bindport = 50000;
		else
			bindport++;

		if (i == 10)
			goto bind_err;
	}

	__set_token_string(tun->token_client);
	tun->fd = s;
	strcat(tun->dev, dev);
	tun->server_addr = c_data.udp_server;
	memcpy(&tun->local_addr, &addr, sizeof(struct sockaddr_in));
	list_add(&tun->list, &c_data.tunnels);
	
	return tun;

bind_err:
	print_log("couldn't bind tunnel socket\n");
free_and_ret:
	free(tun);
	return NULL;
}

int tunnel_add(struct tunnel *tun){
	return ipudp_conf_cmd(IPUDP_CONF_ADD_TUN, (void*)tun);
}

void tunnel_keep_alive(struct timeval *to, int next_to) {
	struct tunnel *t, *tt;

	list_for_each_entry_safe(t, tt, &c_data.tunnels, list) {
		if (do_keepalive(t) < 0) {
			print_log("keepalive failed. closing tunnel...\n");
			tunnel_close(t);
		}
	}
	to->tv_sec = next_to;
	to->tv_usec = 0;
}

void tunnel_close(struct tunnel *t) {
	if (verbose) printf("closing tunnel %d\n", t->tid);

	if (t->tid)
		ipudp_conf_cmd(IPUDP_CONF_DEL_TUN, t);

	close(t->fd);
	list_del(&t->list);
	free(t);
}

void tunnel_close_all(void) { 
	struct tunnel *t, *tt;

	list_for_each_entry_safe(t,tt, &c_data.tunnels, list) {
		tunnel_close(t);
	}
	print_log("all tunnels closed\n");
}

