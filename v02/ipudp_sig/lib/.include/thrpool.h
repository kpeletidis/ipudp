#ifndef	__THRPOOL_H
#define	__THRPOOL_H

#include <stdint.h>
#include <prioq.h>

typedef struct thrpool_id {
	void			*pqi;
	pthread_t		pthread_id;
} thrpool_id_t;

#ifndef	NOTHREADS

extern void thrpool_init(void);
extern int thrpool_req(void (*)(void *), void *, thrpool_id_t *, int);
extern int thrpool_req_excl(void (*)(void *), void *, thrpool_id_t *);
extern void thrpool_set_max(uint32_t);
extern void thrpool_set_min(uint32_t);
extern void thrpool_set_q_size(uint32_t);

extern void thr_specific_set(thrpool_id_t *, void *);
extern void thr_specific_set_self(void *);
extern void *thr_specific_get(thrpool_id_t *);
extern void *thr_specific_get_self(void);

/* Interrupts a blocked select() call */
extern void thr_interrupt(thrpool_id_t *);

#else	/* NOTHREADS */

#define	thrpool_req(handler_func, handler_arg, t,p) (handler_func)(handler_arg)
#define	thrpool_req_excl(handler_func, handler_arg, t) \
				(handler_func)(handler_arg)
#define	thrpool_init()
#define	thrpool_set_max(dummy)
#define	thrpool_set_min(dummy)
#define thr_specific_set(t, x);
#define thr_specific_set_self(x);
#define thr_specific_get(t);
#define thr_specific_get_self();
#define	thr_interrupt(t)

#endif	/* NOTHREADS */

#endif	/* __THRPOOL_H */

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
