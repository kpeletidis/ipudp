#include <sys/stat.h>
#include "ipudp_client.h"

int log_init(void) {	
	if ((log_file = fopen(LOG_FILE_PATH,"w")) < 0) {
			printf("error: couldn't open log file\n");
			return -1;
	}
	return 0;
}

static void __write_log_file(char *p) {
	time_t t = time(NULL);
	struct tm tm = *localtime(&t);
	char time_str[64] = {0};

	sprintf(time_str, "%02d-%02d-%02d %02d:%02d:%02d", 
		tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);

	fprintf(log_file, "%s: %s\n", time_str, p);
}

void 
print_log(char *p, int level) {
	if (level <= verbose) {
		if (background)
			__write_log_file(p);
		else
			fprintf(stderr,"%s\n", p);
	}
}

/*
void 
print_log(char *p) {
	if (verbose)
		fprintf(stderr,"%s", p);	
}
*/

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

