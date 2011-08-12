#ifndef	__PQ_H
#define	__PQ_H

#ifndef	_LIB_MATCH_FUNC
#define	_LIB_MATCH_FUNC
typedef int (*match_func)(void *, void *);
#endif

#ifndef	_LIB_WALK_FUNC
#define	_LIB_WALK_FUNC
typedef void (*walk_func)(void *, void *);
#endif

#ifndef	_LIB_FREE_FUNC
#define	_LIB_FREE_FUNC
typedef void (*free_func)(void *);
#endif

typedef void pq_t;

typedef struct pq_item {
	void	*item;
	int	k;
} pq_item_t;

extern pq_t *pq_create(match_func);
extern void *pq_del(pq_t *, pq_item_t *);
extern void *pq_delmax(pq_t *);
extern void pq_destroy(pq_t *, free_func);
extern void *pq_getmax(pq_t *);
extern int pq_insert(pq_t *, void *, pq_item_t *);
extern void pq_reprio(pq_t *, pq_item_t *);
extern int pq_size(pq_t *);
extern void pq_walk(pq_t *, walk_func, void *);

#endif	/* __PQ_H */

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
