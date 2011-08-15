#include "ipudp_client.h"

int 
sock_init_connect(void) {
	int sock;

	print_log("Connecting to server...\a");
  	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	if ( connect(sock, (const struct sockaddr *)&c_data.tcp_server, sizeof(c_data.tcp_server)) < 0 ) { 
      		print_log("ERROR couldn't connect to server\n");
		close(sock);
		return -1;
	}	

	print_log("connection established\n");
	
	c_data.tcpfd = sock;

	return 0;
}

int
client_init(void) {
	/*TODO*/
	clientshutdown = 0;
		
	INIT_LIST_HEAD(&c_data.tunnels);	
	return 0;
}

int
client_association(char *dev, char *viface) {
	if (do_getvaddr(viface) < 0) {
		printf("error: virtual address request failed\n");
		return -1;
	}
	if (do_reqtun(dev) < 0) {
		printf("error: tunnel establishment failed\n");
		return -1;
	}
	c_data.viface_name = viface;
	c_data.dev = dev;
	return 0;
}

void 
client_keepalive_cycle(int persistent, int to) {
	int try = 0;
	//XXX when multiple tunnel suppost will be added change this
	struct tunnel *tun = (struct tunnel *)&c_data.tunnels.next;

	while(!clientshutdown) {	
		if (do_keepalive(tun) < 0) {
retry:
			if (persistent) {
				if (try > 2) {
					print_log("keepalive failed. couldn't reconnect to server\n");
					break;
				}
				try++;
				if (client_association(c_data.dev, c_data.viface) < 0)
					goto retry;
			}
			else 
				break;
		}
		sleep(to);
	}
	print_log("connection to server lost. closing down...\n");
	tunnel_close(tun);
}

void
client_shutdown(void) {
	clientshutdown = 1;
}
	

void
sock_fin(void) {
	close(c_data.tcpfd);
}

void
client_fini() {
	tunnel_close_all();
	ssl_fini();
	sock_fin();
	ipudp_conf_fini();
	print_log("client shut down\nciaociao\n");
}

