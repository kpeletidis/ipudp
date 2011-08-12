#ifndef	_HASH_H
#define	_HASH_H

#include <stdint.h>
#include "list.h"

typedef uint32_t (*hash_func)(void *, int);

#ifndef	_LIB_MATCH_FUNC
#define	_LIB_MATCH_FUNC
typedef int (*match_func)(void *, void *);
#endif

#ifndef	_LIB_FREE_FUNC
#define	_LIB_FREE_FUNC
typedef void (*free_func)(void *);
#endif

#ifndef	_LIB_WALK_FUNC
#define	_LIB_WALK_FUNC
typedef void (*walk_func)(void *val, void *cookie);
#endif

typedef void htbl_t;

typedef struct htbl_item {
	void *val;
	struct list_head list;
} htbl_item_t;

extern htbl_t *htbl_create(int, hash_func, match_func);
extern void htbl_destroy(htbl_t *, free_func);
extern void htbl_add(htbl_t *, void *, htbl_item_t *);
extern void *htbl_find(htbl_t *, void *);
extern void *htbl_rem(htbl_t *, void *);
extern void *htbl_rem_hit(htbl_t *, htbl_item_t *);
extern void htbl_walk(htbl_t *, walk_func, void *);

/* hash convenience functions */
extern uint32_t hash_string(const char *p, int sz);
extern uint32_t hash_l2addr(const uint8_t *l2a, int l2len, int sz);
extern uint32_t hash_in6_addr(void *v, int sz);
extern uint32_t hash_in_addr(void *v, int sz);

#endif /* _HASH_H */

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
