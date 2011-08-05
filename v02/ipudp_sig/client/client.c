#include "ipudp_client.h"

int 
sock_init_connect(void) {
	int sock, sock2;
	/* TCP */
  	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	if ( connect(sock, (const struct sockaddr *)&c_data.tcp_server, sizeof(c_data.tcp_server)) < 0 ) { 
      		print_log("ERROR couldn't connect to server\n");
		close(sock);
		return -1;
	}	

	print_log("connection established\n");
	
	c_data.tcpfd = sock;

	/* UDP */
  	sock2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	c_data.udpfd = sock2;

	return 0;
}

int
client_init(void) {
	/*TODO*/
	clientshutdown = 0;

	return 0;
}

void
client_shutdown(void) {
	clientshutdown = 1;
}
	

void
sock_fin(void) {
	close(c_data.tcpfd);
	close(c_data.udpfd);
}

void
client_fini() {
	ssl_fini();
	sock_fin();
	ipudp_conf_fini();
	print_log("client shut down\nciaociao\n");
}

