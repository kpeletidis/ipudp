#include "ipudp_server.h"

int verbose = 0; //XXX TODO use a better logging  function with server_data.verbose_level

void usage(void) { 
	printf("Usage: ipudp_server -p <local port> [-a <local addr>] [-u <tun_port>] [-v <verbose level>]\n"
	"\n");
	exit(-1);
}


void signal_handler(int sig) {
	mainloop_terminate();	
}

static int __init(struct server_data *data) {

	if (mainloop_init(NULL) < 0)
		return -1;
	if (verbose) printf("mainloop succesfully initialized\n");

	if (server_init(data) < 0)
		return -1;
	if (verbose) printf("server succesfully initialized\n");

	if (ssl_init(data) < 0)
		return -1;
	if (verbose) printf("server SLL CTX succesfully initialized\n");

	/*if (ctrl_iface_init() < 0 )
		return -1;	
	if (verbose) printf("ctrl_iface succesfully initialized\n");*/
	/**/

	return 0;
}

static void __fini(struct server_data *data) {
	//ssl_fini(data);
	if (verbose) printf("closing ipudp_server\n");
	server_shutdown(data);	
	mainloop_destroy();
}



int 
main(int argc, char **argv)
{
	struct server_data s_data;
	int c;
	int localport = 0, udpport = 0;
	char *localaddr = NULL;

	memset(&s_data, 0, sizeof(struct server_data));

	s_data.verbose_level = 0;
	
	while((c = getopt(argc, argv, "a:p:u:v"))!= -1) {
		switch (c) {
		case 'a':
			localaddr = optarg;
			break;
		case 'p':
			localport = atoi(optarg);
			break;
		case 'u':
			udpport = atoi(optarg);
			break;
		case 'v':
			//s_data.verbose_level = atoi(optarg);
			verbose = 1;
			break;
		
		default:
			usage();
		}
	}

	if (localaddr) {
		if ((s_data.local_addr = inet_pton(AF_INET, localaddr, &s_data.local_addr) < 0)){
			printf("bad local address\n");
			usage();
		}
	}

	if ((localport == 0)) {
		printf("bad or unspecified local port\n");
		usage();
	}
	else
		s_data.local_port = htons(localport);

	if (udpport == 0)
		udpport = DEFAULT_UDP_PORT;

	s_data.tun_port = htons(udpport);

	/*initalizations*/
	signal(SIGTERM, signal_handler);
	signal(SIGINT, signal_handler);	
	signal(SIGKILL, signal_handler);

	if (__init(&s_data) < 0)
		goto exit;

	mainloop_run();

exit:
	__fini(&s_data);

	return 0;
}
