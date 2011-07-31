#include "ipudp_server.h"

#define BACKLOG 7

void 
sock_fini(struct server_data *server) {
	close(server->lfd);
}


int 
sock_init(struct server_data *server) {
	struct sockaddr_in addr;
	int val=1;
	int s;

  	if ((s = socket(AF_INET, SOCK_STREAM, 0) < 0)) {
		printf("sock_init: error in socket()\n");
		return -1;
	}

  	memset(&addr, 0, sizeof(addr));

  	addr.sin_family = AF_INET;
  	addr.sin_port = htons(server->local_port);

	if (server->local_addr != 0)
		memcpy((void *)&addr.sin_addr, &server->local_addr, 4);
	else 
	  	addr.sin_addr.s_addr = INADDR_ANY;
	
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &val,sizeof(val));

  	// Open the socket
  	if(bind(s, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    	printf("server_init: BIND error\n");
		printf("if port < 1024 you might need to be root\n");
		close(s);
    	return -1;
  	}

	if ( (listen(s, BACKLOG)) < 0) {
		printf("server_init: LISTEN error\n");
		close(s);
		return -1;
	}

	if (verbose) printf("server socket in listening..\nsock_init complete\n");
		
	server->lfd = s;

	return 0;
}


int
sock_accept(struct server_data *server) {
	int cfd;
	struct sockaddr_in caddr;
	socklen_t caddrlen;
	char buff[64];

	cfd = accept(server->lfd, (struct sockaddr*)&caddr, &caddrlen);

	if (verbose) 	
		printf("connection accepted from %s, port %d\n", 
			inet_ntop(AF_INET, (void *)&caddr.sin_addr, buff, 
			sizeof(buff)),ntohs(caddr.sin_port));

	return cfd;	
}



