#ifndef _SERVER_H
#define _SERVER_H

#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <linux/types.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h> 
#include <sys/socket.h>
#include <errno.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <netinet/in.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/bio.h>

#include "mainloop.h"
#include "list.h"

#define CIPHERLIST "TLS_RSA_WITH_AES_128_CBC_SHA:TLS_RSA_WITH_AES_256_CBC_SHA"

extern int verbose;

struct 
server_data {
	int lfd;					//tcp listening socket
	__u32 local_addr;
	__u16 local_port;
	int verbose_level;
	struct list_head clients;	//list of active clients
	char *cipher_list;			//list of available cipher methods
};

struct
client_ctx {
	__u32 addr; 				//client IP address
	SSL *ssl;					//SSL session
	SSL_CTX *ssl_ctx;			//SSL context
	int afd;					//accept socket
	BIO *bio_err;				//openssl BIO error
	struct list_head tunnels;	//list of registered tunnel
	int tun_fd;					//udp socket
};

/* server.c */
int server_init(struct server_data *);
void server_shutdown(struct server_data *);

/* ssl.c */
int ssl_init(struct server_data *);
void ssl_fini(struct server_data *);
void ssl_client_fini(struct client_ctx *);

/* sock.c */
int sock_init(struct server_data *);
void sock_fini(struct server_data *);
int sock_accept(struct server_data *);


#endif
