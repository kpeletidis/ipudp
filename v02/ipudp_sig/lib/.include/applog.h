#ifndef	__LIB_APPLOG_H
#define	__LIB_APPLOG_H

#include <syslog.h>
#include <stdint.h>

#define	LIBLOG_MAX_MASK	2 /* uint32_t's */
#define	LIBLOG_MAX_STACK_DEPTH	20

struct dlog_desc {
	char		*desc;
	char		*ctx;
	uint32_t 	bit[LIBLOG_MAX_MASK];
};

#ifdef	DEBUG

extern uint32_t debug_mask;
extern void dlog(char *format, ...);

#define	DLOG(n, args...) \
	do { if ((n) & debug_mask) dlog(args); } while (0)

/*
 * DLOG's a hexdump
 * n: int the debug mask
 * f: const char * for the calling function
 * msg: const char * for a preprended message
 * buf: uint8_t * buffer to be dumped
 * len: int length of of buf
 *
 * example: DLOG_HEXDUMP(DEBUG_ASN1, __FUNCTION__, "the dump: ", buf, len);
 */
#define	DLOG_HEXDUMP(n, f, msg, buf, len) \
	do { if ((n) & debug_mask) applog_hexdump(buf, len, f, msg); } while (0)

#define	DBG(desc, args...) \
	applog_dbg(desc, __FUNCTION__, args)

#define	DBGF(desc, func, args...) \
	applog_dbg(desc, func, args)

#define	DBG_HEXDUMP(desc, msg, buf, len) \
	applog_dhexdump(desc, __FUNCTION__, buf, len, msg)

#define	DBG_STACKTRACE(desc, msg) \
	applog_stacktrace(desc, msg)

#else

#define	DLOG(n, args...)
#define	DLOG_HEXDUMP(n, f, msg, buf, len)
#define	DBG(desc, args...)
#define	DBGF(desc, func, args...)
#define	DBG_HEXDUMP(desc, msg, buf, len)
#define	DBG_STACKTRACE(desc, msg)

#endif

/* Convenience macros */
#define	APPLOG_NOMEM()	applog(LOG_CRIT, "%s: no memory", __FUNCTION__)

/*
 * Timestamp functions and macros - they do nothing unless
 * LOG_TIMESTAMP is defined.
 */
#ifdef	LOG_TIMESTAMP

#include <sys/time.h>
# define timersub(a, b, result)                                               \
  do {                                                                        \
    (result)->tv_sec = (a)->tv_sec - (b)->tv_sec;                             \
    (result)->tv_usec = (a)->tv_usec - (b)->tv_usec;                          \
    if ((result)->tv_usec < 0) {                                              \
      --(result)->tv_sec;                                                     \
      (result)->tv_usec += 1000000;                                           \
    }                                                                         \
  } while (0)

#define	DEFINE_TIMESTAMP_VARS() struct timeval __ts_start[1], __ts_end[1]

#define	TIMESTAMP_START()	gettimeofday(__ts_start, NULL)
#define	TIMESTAMP_END_COMMON(__msg, __start, __end)			\
do {									\
	struct timeval __ts_diff[1];					\
	gettimeofday(__end, NULL);					\
	timersub(__end, __start, __ts_diff);				\
	applog(LOG_INFO, "%-20s: %-15s %2ld.%.6ld", __FUNCTION__, __msg,\
	    __ts_diff->tv_sec, __ts_diff->tv_usec);			\
} while (0)

#define	TIMESTAMP_END(__msg) TIMESTAMP_END_COMMON(__msg, __ts_start, __ts_end)

#define	TIMESTAMP_START_GLOBAL(__ts_gstart) gettimeofday(__ts_gstart, NULL)
#define	TIMESTAMP_END_GLOBAL(__ts_gstart, __msg)			\
do {									\
	struct timeval __ts_end[1];					\
	gettimeofday(__ts_end, NULL);					\
	TIMESTAMP_END_COMMON(__msg, __ts_gstart, __ts_end);		\
} while (0)

#else	/* !LOG_TIMESTAMP */

#define	DEFINE_TIMESTAMP_VARS()
#define	TIMESTAMP_START()
#define	TIMESTAMP_END(__msg)
#define	TIMESTAMP_START_GLOBAL(__ts_gstart)
#define	TIMESTAMP_END_GLOBAL(__msg, __ts_gstart)

#endif	/* LOG_TIMESTAMP */

#define	L_NONE		0
#define	L_STDERR	1
#define	L_SYSLOG	2

extern uint32_t log_all_on[LIBLOG_MAX_MASK];

extern void applog_addlevel(uint32_t *);
extern void applog_clearlevel(uint32_t *);
extern void applog_dbg(struct dlog_desc *, const char *, char *, ...);
extern void applog_printlevels(void);
extern void applog_print_curlevels(void);
extern void applog_dhexdump(struct dlog_desc *, const char *, uint8_t *, int,
    const char *);
extern void applog_stacktrace(struct dlog_desc *, char *);

extern const char *mac2str(uint8_t *, int);
extern const char *mac2str_r(uint8_t *, int, char *buf);
extern int str2mac(const char *, uint8_t *, int *);
extern void applog_hexdump(uint8_t *, int, const char *, const char *);
extern void applog(int prio, char *format, ...);
extern const char **log_get_methods(void);
extern int applog_str2method(const char *);
extern int applog_open(int, char *);

extern int applog_register(struct dlog_desc **);
extern int applog_enable_level(const char *, const char *);
extern int applog_disable_level(const char *, const char *);

#endif	/* __LIB_LOG_H */

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
