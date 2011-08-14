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
#include <net/if.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/bio.h>

#include "mainloop.h"
#include "list.h"

#define CIPHERLIST "DHE-RSA-AES256-SHA"//"TLS_RSA_WITH_AES_128_CBC_SHA:TLS_RSA_WITH_AES_256_CBC_SHA:"
#define DEFAULT_UDP_PORT 50000
#define MAX_LINE_LEN 256

#define TOKEN_LEN 8

#define DEFAULT_FIRST_ADDR 0x0A640001 	//10.100.0.1
#define DEFAULT_LAST_ADDR 0x0A6400FE 	//10.100.0.254
#define DEFAULT_VIFACE_NAME "ipudp0"

#define VIFACE_STR_LEN 12 

#define KEEPALIVE_CHECK_TO 6
#define TUNNEL_MAX_IDLE_TIME 90

enum {		
	IPUDP_CONF_SET_VADDR = 1,
	IPUDP_CONF_ADD_VIFACE,
	IPUDP_CONF_DEL_VIFACE,
	IPUDP_CONF_ADD_TUNNEL,
	IPUDP_CONF_DEL_TUNNEL,
	IPUDP_CONF_ADD_RULE,
};

enum {
	TUN_STATE_WAIT_CREATE = 1,
	TUN_STATE_ESTABLISHED,
};

extern int verbose;

struct 
tunnel {	
	struct list_head list;
	int tid;					//unique tunnel id
	struct sockaddr_in addr; 	//client address:port of the UDP tunnel
	int state;
	int pending_req_seq;
	char token_server[2*TOKEN_LEN + 1];
	char token_client[2*TOKEN_LEN + 1];
	struct timeval last_ka;
};

struct pending_tun_req {
	struct list_head list;
	int token;
	struct client *client;
};

struct vaddr {
	struct list_head list;
	__u32 addr;                     //overlay addr
	struct client *client;          //client to which the addr is assigned
};
struct 
server_data {
	int lfd;					//tcp listening socket
	int tunfd;					//udp socket
	char dev_name[IFNAMSIZ];
	__u32 local_addr;
	__u16 local_port;
	__u16 tun_port;				//udp listening port
	int verbose_level;
	struct list_head clients;	//list of active clients
	SSL_CTX *ssl_ctx;			//SSL context
	struct list_head v_addrs;
								//list of allocated client overlay addresses
	char viface_name[VIFACE_STR_LEN + 1];
	__u32 first_addr;			//first address - server overlay address
	__u32 last_addr;
};

struct
client {
	struct list_head list;
	struct sockaddr_in addr; 	//client address:port of TCP connection
	SSL *ssl;					//SSL session
	int cfd;					//connection socket
	BIO *bio_err;				//openssl BIO error
	struct list_head tunnels;	//list of registered tunnel
	X509 *cert;					//X509 client certificate
	__u32 v_addr;				//assigned overlay address
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
int ssl_write_n(SSL *, unsigned char *, int);

/* sock.c */
int sock_init(struct server_data *);
void sock_fini(struct server_data *);
int sock_accept(struct server_data *);
void server_accept_cb(int, void *, void *);
void client_shutdown(struct client *, struct server_data *);

/* proto.c */
void proto_handle_msg(char *, int, struct client *, struct server_data *);
void proto_handle_udp_msg(char *, int, struct sockaddr_in *, struct server_data*);

/* ipudp_conf.c */
int ipudp_conf_cmd(int, void **);
int ipudp_conf_init(struct server_data *); 
int ipudp_conf_fini(struct server_data *); 

/* tunnel.s */
void tunnel_close_all(struct server_data *, struct client *);
void tunnel_set_token(char *);
int tunnel_configure(struct server_data *, struct client *, struct tunnel *, struct sockaddr_in *);
void tunnel_close(struct server_data *, struct tunnel *);
int tunnel_set_rule(struct server_data *, struct client *, struct tunnel *);
void tunnel_check_keepalive(void *, void *);

#endif
