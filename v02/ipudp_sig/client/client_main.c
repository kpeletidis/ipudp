#include "ipudp_client.h"

#include <appconsole.h>

struct client_data c_data;


void usage(void) { printf("Usage: client -p <port> -a <server address>" 
		"[-u <udp_port>] [-c (console)] [-v (verbose)]\n"); }


static void 
sighand(int s)
{
	client_shutdown();
}


static int 
do_select(int cfd) {
        fd_set fds[1];
        int maxfd;
        struct timeval *tv;

        maxfd = cfd;
        //maxfd = max(lfd, xxx);
	
	while (!clientshutdown) {
                FD_ZERO(fds);
                FD_SET(cfd, fds);
                //FD_SET(xxx, fds);
		
		tv = NULL;
		
		if (select(maxfd + 1, fds, NULL, NULL, tv) < 0) {
                        if (errno == EINTR) {
                                continue;
                        }
                        print_log("do_select: select error\n");
                        return (-1);
                }


                if (FD_ISSET(cfd, fds)) {
                 	console_read_char();    
                }
	
	}

	return 0;
}


int main(int argc, char **argv) {
	int c = 0;
	int console = 0;
	int port = 0, uport = 0;
	char *addrstr;
	verbose = 0;

	while((c = getopt(argc, argv, "p:a:cv"))!= -1) {
		switch (c) {
		case 'p':
			port = atoi(optarg);
			break;
		case 'v':
			verbose = 1;
			break;
		case 'c':
			console = 1;
			break;
		case 'a':
			addrstr = optarg;
			break;
		case 'u':
			uport = atoi(optarg);
			break;
		default:
			usage();
			exit(-1);				}
	}
	if (!(port) || !(addrstr)) {
		usage();
		exit(-1);
	}
	if (!uport)
		uport = DEFAULT_UDP_PORT;
	

	/*Initialization*/
	memset(&c_data, 0, sizeof(struct client_data));

	/*TCP server addr*/
  	c_data.tcp_server.sin_family = AF_INET;
  	c_data.tcp_server.sin_port = htons(port);
  	if (inet_pton(AF_INET, addrstr, &c_data.tcp_server.sin_addr)<0) {
		print_log("bad server ip address\n");
		exit(-1);
	}

	/*UDP server addr*/
	c_data.udp_server.sin_family = AF_INET;
  	c_data.udp_server.sin_port = htons(uport);
  	inet_pton(AF_INET, addrstr, &c_data.udp_server.sin_addr);

	if (console) {
		if (console_ini() < 0)
			exit(-1);
	}
		
	if (client_init() < 0) {
		print_log("client_init() error\n");
		goto quit;
	}	
	if (sock_init_connect() < 0)
		goto quit;

	if ((ssl_init() < 0))
		goto quit;

	/**/

	signal(SIGINT, sighand);
    signal(SIGTERM, sighand);

	if (console)
		do_select(0);
	else 
		test_send();

quit:
    client_fini();
	console_fini();

	exit(0);
}
