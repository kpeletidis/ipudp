#include <appconsole.h>

#include "ipudp_client.h"

static void
cmd_debugon(char *b) {
	verbose = 1;
}


static void
cmd_debugoff(char *b) {
	verbose = 0;
}


static void 
cmd_reqtun(char *b) {
	char *dev;
	struct ifreq ifr;

	APPCONSOLE_FIRST_ARG(b, dev, "missing real device name. Es: req_tun eth0\n");
	
	strncpy(ifr.ifr_name,dev,IFNAMSIZ);
	if (ioctl(c_data.tcpfd, SIOCGIFINDEX, &ifr) == -1) {
		printf("%s: device not found\n",dev);
		return;
	}
	do_reqtun(dev);
}

static void 
cmd_getvaddr(char *b) {
	char *viface;

	APPCONSOLE_FIRST_ARG(b, viface, "missing viface name. Es: get_vaddr ipudp0\n");

	if (strlen(viface) > VIFACE_STR_LEN) {
		printf("viface name too long. MAX 12 chars\n");
		return;
	}
		
	do_getvaddr(viface);
}

static void
cmd_quit(char *b) {
	client_shutdown();
}

static cons_info_t commands[] = {
	{ "q",			"quit", 1, cmd_quit },
	{ "debug_on",	"enable debug", 8, cmd_debugon },
	{ "debug_off",	"disable debug", 8, cmd_debugoff },
	{ "get_vaddr",	"request virtual address", 5, cmd_getvaddr},
	{ "req_tun",	"establish ipudp tunnel", 5, cmd_reqtun},
};

static void
exit_handler(void) {
	client_fini();
}

int
console_ini(void) {
	int ret;

	ret = console_init(0, 1, commands, sizeof (commands) / sizeof (*commands),
			     exit_handler, "ipudp:$ ");
	if (ret > 0)
		print_log("console sucesfully initialized", LOG_LEVEL_NOTIFICATION);
	return ret;
}

void 
console_fini(void) {
	console_exit();
	printf("\n");
}

