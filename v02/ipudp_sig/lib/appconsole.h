#ifndef	__CONSOLE_H
#define	__CONSOLE_H

#define	CONSOLE_BUFSIZ	128

typedef void (*cons_cmd_handler)(char *);
typedef void (*cons_exit_handler)(void);

typedef struct cons_info {
	const char	*cmdstr;
	const char	*helpstr;
	int		cmdlen;
	cons_cmd_handler cmd_handler;
} cons_info_t;

/* Used often - finds first argument */
#define	APPCONSOLE_FIRST_ARG(__cmd, __setto, __errmsg) \
    do {					\
	__setto = strchr(__cmd, ' ');		\
	if (!(__setto)) {			\
		printf(__errmsg); return;	\
	}					\
	*(__setto)++ = 0;			\
	while (*(__setto) == ' ') (__setto)++;	\
	if (*(__setto) == 0) {			\
		printf(__errmsg); return;	\
	}					\
    } while (0)

#define	APPCONSOLE_NEXT_ARG(__cmd, __setto, __errmsg) \
	APPCONSOLE_FIRST_ARG(__cmd, __setto, __errmsg)

extern void console_exit(void);
extern int console_init(int, int, cons_info_t *, int, cons_exit_handler,
    const char *);
extern void console_read(void);
extern void console_read_char(void);

#endif	/* __CONSOLE_H */

