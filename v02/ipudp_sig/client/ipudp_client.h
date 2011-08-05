#ifndef _TFTS_H
#define _TFTS_H

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/bio.h>

#include "list.h"
#include "mainloop.h"

#define KEYFILE "./certs/user.key"
#define CERTFILE "./certs/user.pem"
#define CAPATH "./certs"
#define DHFILE "./certs/dh.pem"

#define CIPHER_LIST "ALL"
#define DEFAULT_UDP_PORT 50000
#define MAX_LINE_LEN 256

#define VIFACE_STR_LEN 12 

typedef uint32_t __u32; 
typedef uint16_t __u16; 
typedef uint8_t __u8; 

enum {
		IPUDP_CONF_SET_VADDR = 1,
		IPUDP_CONF_ADD_VIFACE,
		IPUDP_CONF_DEL_VIFACE,
};

extern struct client_data c_data;

struct client_data {
	struct sockaddr_in tcp_server;
	struct sockaddr_in udp_server;
	int tcpfd;
	int udpfd;
	__u32 vaddr;
	char viface[VIFACE_STR_LEN + 1];
};

int clientshutdown;
int verbose;

SSL *ssl;
SSL_CTX *ssl_ctx;

/*utils.c*/
void print_log(char *);
void test_send(void);

/*ssl.c*/
int ssl_init(void);
int ssl_readline(SSL *, void *, int, int *);
int ssl_write_n(SSL *, unsigned char *, int);
int ssl_read_n(SSL *, unsigned char *, int);
int ssl_check_error(SSL *, int);
void ssl_fini(void);

/*client.c*/
int sock_init_connect(void);
int client_init(void);
void client_fini(void);
void client_shutdown(void);

/*console.c*/
int console_ini(void);
void console_fini(void);

/*proto.c*/
int do_getvaddr(char *);

/*ipudp_conf.c*/
int ipudp_conf_init(void);
int ipudp_conf_fini(void);
int ipudp_conf_cmd(int, void*);

#endif
