#include <sys/stat.h>
#include "ipudp_client.h"

void 
print_log(char *p) {
	if(verbose)
		fprintf(stderr,"%s", p);	
	else
		;
}

int 
daemonize(void)
{
	pid_t pid, sid;

	if ( getppid() == 1 ) return 0;
	
	pid = fork();
	if (pid < 0) {
		return(-1);
	}

	if (pid > 0) {
		exit(0);
	}

	umask(0);

	sid = setsid();
	if (sid < 0) {
		return(-1);
	}

	if ((chdir("/")) < 0) {
		return(-1);
	}

	if (!(freopen( "/dev/null", "r", stdin))) {
		printf("Couldn't redirect stdin\n");
		return(-1);
	}
	
	if (!(freopen( "/dev/null", "w", stdout))) {
		printf("Couldn't redirect stdout\n");
		return(-1);
	}
	
	if (!(freopen( "/dev/null", "w", stderr))) {
		printf("Couldn't redirect stderr\n");
		return(-1);
	}

	return 0;
}

