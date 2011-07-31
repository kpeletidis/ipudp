#include "ipudp_server.h"

void
server_accept_cb(int sock, void *server, void *user_ctx) {
	sock_accept((struct server_data *)server);

	return;
}

int 
server_init(struct server_data *server) {
	/* configuration init XXX TODO */

	/* init tcp socket */
	if (sock_init(server) < 0){
		if (verbose) printf("server_init: error initializing sockets\n");
		return -1;
	}
	
	//set accept callback into mainloop
	if ((mainloop_register_sock(server->lfd, EVENT_TYPE_READ, server_accept_cb, (void *)server, NULL) < 0)) {
		printf("server_init: mainloop_register_socket error\n");
		return -1;
	}
		
	if (verbose) printf("server_init: DONE!\n");	
	return 0;
}

void 
server_shutdown(struct server_data *server) {
	/* close tcp socket */
	sock_fini(server);
	return;
}
