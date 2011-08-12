#ifndef	__TIMER_H
#define	__TIMER_H

#include <sys/time.h>
#include <prioq.h>

typedef void (*timer_func)(void *);

typedef struct timer_item {
	struct timeval	tv;
	timer_func	func;
	void		*arg;
	pq_item_t	pqi;
} timer_item_t;

#define timerisset(tvp)        ((tvp)->tv_sec || (tvp)->tv_usec)
#define timerclear(tvp)        ((tvp)->tv_sec = (tvp)->tv_usec = 0)

#define	timer_init_item(_ti)	timerclear(&(_ti)->tv)

extern struct timeval *timer_check(struct timeval *);
extern void timer_clear(timer_item_t *);
extern void timer_clear_sync(timer_item_t *);
extern int timer_init(void);
extern int timer_set(struct timeval *, timer_func, void *, timer_item_t *);
extern void timer_walk(walk_func, void *);

#endif	/* __TIMER_H */

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
