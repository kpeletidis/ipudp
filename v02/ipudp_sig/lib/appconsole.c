#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifdef	USE_READLINE
#include <pthread.h>
#include <readline/readline.h>
#include <readline/history.h>
#endif

#include "appconsole.h"

static cons_info_t *cmds;
static int cmd_cnt;
static FILE *infile, *outfile;
cons_exit_handler exit_handler;
static const char *cons_prompt;

#ifdef	THREADS
static pthread_t cons_tid;
#endif

static void
dohelp(void)
{
	int i;

	for (i = 0; i < cmd_cnt; i++) {
		fprintf(outfile, "%s\t%s\n", cmds[i].cmdstr, cmds[i].helpstr);
	}
	fprintf(outfile, "? help\tShows help\n");
}

static void
docmd(char *buf)
{
	int i;

	if (*buf == 0 || *buf == '\n') {
		return;
	}
	if (*buf == '?' || strncasecmp(buf, "help", 4) == 0) {
		dohelp();
		return;
	}

	for (i = 0; i < cmd_cnt; i++) {
		if (strncasecmp(cmds[i].cmdstr, buf, cmds[i].cmdlen) == 0) {
			cmds[i].cmd_handler(buf);
			return;
		}
	}

	fprintf(outfile, "Unknown command\n");
	return;
}

void
console_read(void)
{
	char buf[CONSOLE_BUFSIZ], *cp;

	if ((cp = fgets(buf, CONSOLE_BUFSIZ, infile)) == NULL) {
		exit_handler();
		return;
	}

	docmd(cp);
	fprintf(outfile, "%s", cons_prompt);
	fflush(outfile);
}

#ifdef	USE_READLINE
static void
handle_rlinput(char *rd)
{
	if (rd == NULL) {
		exit_handler();
		rl_cleanup_after_signal();
		rl_reset_terminal(NULL);
		pthread_exit(NULL);
	}
	if (*rd != 0) {
		add_history(rd);
	}
	docmd(rd);
	free(rd);
}

#ifdef	THREADS
static void *
console_thr(void *a)
{
	char *rd;

	for (;;) {
		rd = readline(cons_prompt);
		handle_rlinput(rd);
	}
}
#endif	/* THREADS */

static char *
possible_cmds(const char *text, int state)
{
	static int len, idx;

	if (state == 0) {
		idx = 0;
		len = strlen(text);
	}

	for (; idx < cmd_cnt; idx++) {
		if (strncmp(cmds[idx].cmdstr, text, len) == 0) {
			return (strdup(cmds[idx++].cmdstr));
		}
	}

	return (NULL);
}
#endif

void
console_read_char(void)
{
#ifdef	USE_READLINE
	rl_callback_read_char();
#endif
}

int
console_init(int infd, int outfd, cons_info_t *ci, int cnt,
    cons_exit_handler exitcb, const char *prompt)
{
	if (cmds != NULL) {
		return (-1);
	}
	cmds = ci;
	cmd_cnt = cnt;
	exit_handler = exitcb;
	cons_prompt = prompt;

	infile = infd == 0 ? stdin : fdopen(infd, "r");
	outfile = outfd == 1 ? stdout : fdopen(outfd, "w");

#ifdef	USE_READLINE
	rl_instream = infile;
	rl_outstream = outfile;
	rl_completion_entry_function = possible_cmds;
#ifdef	THREADS
	if (pthread_create(&cons_tid, NULL, console_thr, NULL) != 0) {
		return (-1);
	}
#else
	rl_callback_handler_install(prompt, handle_rlinput);
#endif	/* THREADS */
#else
	fprintf(outfile, "%s", prompt);
	fflush(outfile);
#endif	/* USE_READLINE */

	return (0);
}

void
console_exit(void)
{
#ifdef	USE_READLINE
	rl_cleanup_after_signal();
	rl_reset_terminal(NULL);
#endif
}

