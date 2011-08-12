#include "ipudp_server.h"

#define BACKLOG 7


void 
sock_fini(struct server_data *server) {
	close(server->lfd);
	close(server->tunfd);
}


int 
sock_init(struct server_data *server) {
	struct sockaddr_in addr;
	int val=1;
	int s1,s2;
	int ret = 0;

	/* TCP listening socket */
  	
	if ( (s1 = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket()");
		ret = -1;
		goto ret;
	}

  	memset(&addr, 0, sizeof(addr));

  	addr.sin_family = AF_INET;
  	addr.sin_port = server->local_port;

	if (server->local_addr != 0)
		memcpy((void *)&addr.sin_addr.s_addr, &server->local_addr, 4);
	else 
	  	addr.sin_addr.s_addr = INADDR_ANY;
	
  	// set up the socket
	if (setsockopt(s1, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)) == -1) {
		perror("setsockopt");
		ret = -1;
		goto ret_close_s1;
	}

  	if(bind(s1, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("bind");
		ret = -1;
		goto ret_close_s1;
  	}

	if ((listen(s1, BACKLOG)) < 0) {
		printf("sock_init: LISTEN error\n");
		ret = -1;
		goto ret_close_s1;
	}

	server->lfd = s1;

	if (verbose) printf("binding udp socket on port %d\n", ntohs(server->tun_port));
	/* UDP tunnel socket */
	if ( (s2 = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		printf("sock_init: error in SOCKET for udp socket\n");
		ret = -1;
		goto ret_close_s1;
	}

  	memset(&addr, 0, sizeof(addr));

  	addr.sin_family = AF_INET;
  	addr.sin_port = server->tun_port;

	if (server->local_addr != 0)
		memcpy((void *)&addr.sin_addr, &server->local_addr, 4);
	else 
	  	addr.sin_addr.s_addr = INADDR_ANY;
	
	setsockopt(s2, SOL_SOCKET, SO_REUSEADDR, &val,sizeof(val));

  	// Open the socket
  	if(bind(s2, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    	printf("sock_init: BIND error for udp socket\n");
		printf("if port < 1024 you might need to be root\n");
		ret = -1;
		goto ret_close_s2;
  	}

	server->tunfd = s2;
	if (verbose) printf("sock_init complete\n");
	
	return ret;

ret_close_s2:
	close(s2);
ret_close_s1:
	close(s1);
ret:
	return ret;
}

void
udp_recv_cb(int sock, void *server, void *user_ctx) {
	char buf[2024] = {0};
	struct server_data *s = (struct server_data *)server;
	struct sockaddr from;
	int fromlen, l;

	if ((l = recvfrom(s->tunfd, (void *)buf, 2024, 0, &from, (size_t *)&fromlen)) > 0) {
#ifdef DBG
		printf("received %d bytes from udp socket %s\n", l, buf);
#endif
		proto_handle_udp_msg(buf, l, (struct sockaddr_in*)&from, s);
	}
	else {
		if (verbose) printf("udp_recv_cb: read error\n");
	}
	return;
}

int 
server_init(struct server_data *server) {
	char *viface = DEFAULT_VIFACE_NAME;

	/* configuration init XXX TODO */
	server->first_addr = DEFAULT_FIRST_ADDR;
	server->last_addr = DEFAULT_LAST_ADDR;
	
	if (strlen(viface) > VIFACE_STR_LEN ){ 
		if (verbose) printf("server_init: bad viface name\n");
		return -1;
	}
	strcat(server->viface_name, viface);

	if (server->first_addr == 0xffffffff) {
		if (verbose) printf("server_init: bad first addres\n");
		return -1;
	}

	/* lists init*/
	INIT_LIST_HEAD(&server->clients);	
	INIT_LIST_HEAD(&server->v_addrs);	

	/* init tcp socket */
	if (sock_init(server) < 0){
		if (verbose) printf("server_init: error initializing sockets\n");
		return -1;
	}
	
	/* set accept callback into mainloop */
	if ((mainloop_register_sock(server->lfd, EVENT_TYPE_READ, server_accept_cb, (void *)server, NULL) < 0)) {
		printf("server_init: mainloop_register_socket error\n");
		return -1;
	}

	/* set tun socket callback into mainloop */
	if ((mainloop_register_sock(server->tunfd, EVENT_TYPE_READ, udp_recv_cb, (void *)server, NULL) < 0)) {
		printf("server_init: mainloop_register_socket error\n");
		return -1;
	}

		
	if (verbose) printf("server_init: DONE!\n");	
	return 0;
}

void 
server_shutdown(struct server_data *server) {
	struct client *n,*m;
	struct list_head *l = &server->clients;

	/* free clients */
	list_for_each_entry_safe(n, m, l, list) {
		client_shutdown(n, server);	
	}
	/* close tcp listen and udp socket */
	sock_fini(server);


	return;
}

void
client_conn_cb(int sock, void *s, void *c) {
	int ret, len;
	struct client *client = (struct client *)c;
	struct server_data *server = (struct server_data *)s;
	char buf[2024];
	SSL *ssl = client->ssl;

	ret = ssl_readline(ssl, buf, MAX_LINE_LEN, &len);
	switch(SSL_get_error(ssl, ret)){

	case SSL_ERROR_NONE:
		//serve the request
#ifdef DBG
		printf("readline from ssl socket %s - %d bytes\n", buf, len);
#endif

		proto_handle_msg(buf, len, client, server);
		break;

	case SSL_ERROR_ZERO_RETURN:
		if (verbose) printf("SSL session shutdown\n");
		goto exit;

	case SSL_ERROR_SYSCALL:
		if (verbose) printf("SSL Error: Premature close\n");
		goto exit;

	default:
		if (verbose) printf("SSL read problem\n");
		goto exit;
	}

	return;

exit:
	client_shutdown(client, server);		
	return;
}


int
sock_accept(struct server_data *server) {
	int cfd;
	struct sockaddr_in caddr;
	struct client *c;
	socklen_t caddrlen;
	char buff[64];

	cfd = accept(server->lfd, (struct sockaddr*)&caddr, &caddrlen);

	if (cfd < 0) {
		if (verbose) printf("sock_accept: ACCEPT error\n");
		goto ret;
	}

	if (verbose) 	
		printf("TCP connection accepted from %s, port %d\n", 
			inet_ntop(AF_INET, (void *)&caddr.sin_addr, buff, 64)
					,ntohs(caddr.sin_port));

	c = (struct client *) malloc(sizeof(struct client));

	INIT_LIST_HEAD(&c->tunnels);	
	memcpy(&c->addr, &caddr, sizeof(struct sockaddr_in));
	c->cfd = cfd;

	list_add(&c->list, &server->clients);	
	if (verbose) printf("client added\n");

	if (ssl_connection_init(c, server) < 0) {
		if (verbose) printf("error in ssl_connection_init\n");
		goto err;
	}
	else {	
		if ((mainloop_register_sock(cfd, EVENT_TYPE_READ, client_conn_cb, (void *)server, (void *)c) < 0)) {
			printf("sock_accept: mainloop_register_socket error\n");
			goto err;
		}
	}

ret:
	return cfd;	
err:
	close(cfd);
	list_del(&c->list);
	free(c);
	return -1;
}

void
server_accept_cb(int sock, void *server, void *user_ctx) {
	if (sock_accept((struct server_data *)server) < 0) { 
		if (verbose) printf("server_accept_cb error\n");
	}
	else {
		if (verbose) printf("server_accept_cb: done\n");
	}
		
	return;
}

void
client_shutdown(struct client *c, struct server_data *s) {
	char buf[32];
	struct vaddr *a, *b;

	if (verbose) printf("shutting down client %s:%d\n", inet_ntop(AF_INET, &c->addr.sin_addr, buf, 32), ntohs(c->addr.sin_port));
	
	ssl_client_fini(c);	
	mainloop_unregister_sock(c->cfd, EVENT_TYPE_READ);
	close(c->cfd);
	list_del(&c->list);
	
	list_for_each_entry_safe(a, b, &s->v_addrs, list) { 
		if (a->client == c) {
			list_del(&a->list);
			free(a);
		}
	}

	/* TODO close tunnels, free vipa, remove all timeouts */
	tunnel_close_all(s, c);
	free(c);
	return;
}
