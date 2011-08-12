#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "appconsole.h"

static void cntcb(char *);

static void
showcb(char *buf)
{
	printf("%s", buf);
	printf("\n");
}

static void
exitcb(void)
{
	exit(0);
}

static cons_info_t cmds[] = {
	{ "show", "Shows test info", 3, showcb },
	{ "count", "Shows command count", 2, cntcb },
	{ "shell", "Same as show", 3, showcb }
};

static void
cntcb(char *buf)
{
	printf("%d\n", sizeof (cmds) / sizeof (*cmds));
}

int
main(int argc, char **argv)
{
#ifdef	NOTHREADS
	fd_set fds;
	int rv;
#endif

	if (console_init(0, 1, cmds, sizeof (cmds) / sizeof (*cmds), exitcb,
	    "test> ") < 0) {
		fprintf(stderr, "console_init failed\n");
		exit(1);
	}

#ifdef	NOTHREADS
	FD_ZERO(&fds);
	FD_SET(0, &fds);
	while ((rv = select(1, &fds, NULL, NULL, NULL)) >= 0) {
		if (FD_ISSET(0, &fds)) {
#ifdef	USE_READLINE
			console_read_char();
#else
			console_read();
#endif	/* USE_READLINE */
		}
		else {
			printf("fd other than stdin ready\n");
		}
	}
#else
	for (;;) {
		sleep(20);
	}
#endif

	exit(0);
}

/*
 * Overrides for Emacs so that we follow Linus's tabbing style.
 * Emacs will notice this stuff at the end of the file and automatically
 * adjust the settings for this buffer only.  This must remain at the end
 * of the file.
 * ---------------------------------------------------------------------------
 * Local variables:
 * c-file-style: "linux"
 * End:
 */
