#include "ipudp_client.h"

#include <appconsole.h>

struct client_data c_data;
int background = 0;
int verbose = 0;
int clientshutdown = 0;
FILE *log_file = NULL;

void usage(void) { 
		printf("\nUsage: client -p <port> -a <server address> [-u <tunnel_port>] [-c (console)]" 
		" [-i <dev>] [-n <viface_name>] [-k <sec>] [-b (background)] [-P (persistent)] [-v (verbose)]\n"
		"-p <port>: TCP server port\n"
		"-a <address>: server IP address\n"
		"-u <tunnel_port>: UDP server tunneling port - optional. Default: %d\n"
		"-c: starts interactive console mode. Press TAB for command list\n"
		"-i <dev>: set the local outgoning tunnel interface. Ignored in console mode. Mandatory optherwise\n"
		"-n <viface_name>: set the virtual interface name. Ignored in console mode. Default: %s\n"
		"-k <sec>: set keepalive time in seconds\n"
		"-b: demonize the program\n"
		"-P: set persistent mode. If  \"tunnel connectivity\" is lost, a new tunnel is automatically established\n"
		"-v: set verbose mode - debug\n\n"
		"es: 1) interactive console mode: client -p 9000 -a 10.0.0.1 -c\n"
		"    2) background mode: client -p 9000 -a 10.0.0.1 -i eth0 -n ipudp0 -b\n"
		"\n",
		DEFAULT_UDP_PORT, DEFAULT_VIFACE_NAME); 
	exit(-1);
}

static void 
sighand(int s)
{
	client_shutdown();
}

static int 
do_select(int cfd, int to_sec) {
	fd_set fds[1];
	int maxfd;
	struct timeval timeout;
	
	timeout.tv_sec = to_sec;
	timeout.tv_usec = 0;

	maxfd = cfd;
	//maxfd = max(lfd, xxx);

	while (!clientshutdown) {
                FD_ZERO(fds);
                FD_SET(cfd, fds);
                //FD_SET(xxx, fds);
		
		if (select(maxfd + 1, fds, NULL, NULL, &timeout) < 0) {
                        if (errno == EINTR) {
                                continue;
                        }
                        print_log("do_select: select error", LOG_LEVEL_IMPORTANT);
                        return (-1);
                }
                if (FD_ISSET(cfd, fds))
                 	console_read_char();
				else
					tunnel_keep_alive(&timeout, to_sec);
	}
	return 0;
}


int main(int argc, char **argv) {
	int c = 0;	
	int console = 0;
	int port = 0, uport = 0, ka_time = 0, persistent = 0;
	char *addrstr = NULL, *viface = NULL, *dev = NULL;

	while((c = getopt(argc, argv, "u:p:a:n:k:i:bcvP"))!= -1) {
		switch (c) {
		case 'u':
			uport = atoi(optarg);
			break;
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
		case 'i':
			dev = optarg;
			break;
		case 'n':
			viface = optarg;
			break;
		case 'k':
			ka_time = atoi(optarg);
			break;
		case 'b':
			background = 1;
			break;
		case 'P':
			persistent = 1;
			break;
		default:
			usage();
			exit(-1);
		}
	}
	if (!(port) || !(addrstr)) {
		printf("Error: both -a <address> and -p <port> must be specified\n");
		usage();
	}

	if (!uport)
		uport = DEFAULT_UDP_PORT;
	
	if (!ka_time)
		ka_time = DEFAULT_KEEPALIVE_TIMEOUT;	

	if (!viface)
		viface = DEFAULT_VIFACE_NAME;

	if ((!console) && (!dev)) {
		printf("Error: either -c or -i <dev> must be specified. If console mode is not used," 
				"the name of the outgoing tunnel interface must be specified\n");
		usage();
	}

	/*Initialization*/
	if (background) {
		if (log_init() < 0) {
			printf("error: log_init failed\n");
			exit(-1);
		}
	}

	memset(&c_data, 0, sizeof(struct client_data));

	/*TCP server addr*/
  	c_data.tcp_server.sin_family = AF_INET;
  	c_data.tcp_server.sin_port = htons(port);
  	if (inet_pton(AF_INET, addrstr, &c_data.tcp_server.sin_addr)<0) {
		printf("bad server ip address");
		exit(-1);
	}

	/*UDP server addr*/
	c_data.udp_server.sin_family = AF_INET;
  	c_data.udp_server.sin_port = htons(uport);
  	inet_pton(AF_INET, addrstr, &c_data.udp_server.sin_addr);

	if (client_init() < 0) {
		print_log("client_init() error", LOG_LEVEL_IMPORTANT);
		goto quit;
	}

	if (ipudp_conf_init() < 0) {
		print_log("ipudp_conf_init() error", LOG_LEVEL_IMPORTANT);
		goto quit;
	}

	if (sock_init_connect() < 0)
		goto quit;

	if ((ssl_init() < 0))
		goto quit;
	
	if (console) {
		if (console_ini() < 0) {
			console = 0;
			goto quit;
		}
	}
	/**/

	signal(SIGINT, sighand);
    signal(SIGTERM, sighand);
    signal(SIGKILL, sighand);

	if (console)
		do_select(0, ka_time);
	else {
		if (client_association(dev, viface) < 0) 
			goto quit;
		if (background) {
			if (daemonize() < 0) {
				printf("Error: couldn't demonize. Exit\n");
				goto quit;
			}
		}
		client_keepalive_cycle(persistent, ka_time);
	}

quit:
    client_fini();
	if (console)
		console_fini();

	return 0;
}
