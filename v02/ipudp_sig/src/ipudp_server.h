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
#define DEFAULT_UDP_PORT 50000
#define MAX_LINE_LEN 256

extern int verbose;

struct 
server_data {
	int lfd;					//tcp listening socket
	int tunfd;					//udp socket
	__u32 local_addr;
	__u16 local_port;
	__u16 tun_port;				//udp listening port
	int verbose_level;
	struct list_head clients;	//list of active clients
	SSL_CTX *ssl_ctx;			//SSL context
};

struct
client {
	struct list_head list;
	struct sockaddr_in addr; 	//client address:port
	SSL *ssl;					//SSL session
	int cfd;					//connection socket
	BIO *bio_err;				//openssl BIO error
	struct list_head tunnels;	//list of registered tunnel
	X509 *cert;					//X509 client certificate
};

/* server.c */
int server_init(struct server_data *);
void server_shutdown(struct server_data *);

/* ssl.c */
int ssl_init(struct server_data *);
void ssl_fini(struct server_data *);
void ssl_client_fini(struct client *);
int ssl_connection_init(struct client *, struct server_data *);
int ssl_readline(SSL *, void *, int, int *);

/* sock.c */
int sock_init(struct server_data *);
void sock_fini(struct server_data *);
int sock_accept(struct server_data *);
void server_accept_cb(int, void *, void *);
void client_shutdown(struct client *, struct server_data *);

/* proto.c */
void proto_handle_msg(char *, int, struct client *, struct server_data *);


#endif
