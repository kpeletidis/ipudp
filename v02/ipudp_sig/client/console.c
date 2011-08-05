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

/*	
static void
cmd_getfile(char *b)
{
	char * filename;
	char cmd[100];

	APPCONSOLE_FIRST_ARG(b, filename, "missing file name. Usage: cmd filename\n");
	
	sprintf(cmd, "GET_FILE %s\n", filename);

	printf("command: %s", cmd);
	do_getfile(cmd);
}*/

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
	{ "q",     	"quit", 1, cmd_quit },
	{ "debug_on",	"enable debug", 8, cmd_debugon },
	{ "debug_off",	"disable debug", 8, cmd_debugoff },
	{ "get_vaddr",	"disable debug", 3, cmd_getvaddr},
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
		print_log("Console sucesfully initialized\n");
	return ret;
}

void 
console_fini(void) {
	console_exit();
	printf("\n");
}

