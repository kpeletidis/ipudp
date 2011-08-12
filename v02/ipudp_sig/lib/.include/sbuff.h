#ifndef	_LIB_SBUFF_H
#define	_LIB_SBUFF_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

struct sbuff {
	uint8_t		*head;
	uint8_t		*data;
	int		rem;
	int		len;
	int		truesize;
	int		refcnt;
};

static __inline__ void
sbuff_init(struct sbuff *b, size_t sz, void *data)
{
	b->head = b->data = data;
	b->truesize = b->rem = sz;
	b->len = 0;
	b->refcnt = 1;
}

static __inline__ struct sbuff *
sbuff_alloc(size_t sz)
{
	struct sbuff *b = malloc(sizeof (*b) + sz);

	if (b != NULL) {
		sbuff_init(b, sz, b + 1);
	}

	return (b);
}

static __inline__ void
sbuff_free(struct sbuff *b)
{
	if (--b->refcnt == 0) {
		free(b);
	}
}

static __inline__ void
sbuff_hold(struct sbuff *b)
{
	b->refcnt++;
}

/*
 * Add data to a buffer. Returns -1 if the buffer would be overrun, 0
 * on success.
 */
static __inline__ int
sbuff_put(struct sbuff *b, const void *d, size_t dlen)
{
	if (dlen > b->rem) {
		return (-1);
	}
	memcpy(b->data, d, dlen);
	b->rem -= dlen;
	b->len += dlen;
	b->data += dlen;

	return (0);
}

/*
 * List sbuff_put(), but doesn't copy any data; just does bounds check and
 * advances the data pointer and size counters.
 */
static __inline__ int
sbuff_advance(struct sbuff *b, size_t dlen)
{
	if (dlen > b->rem) {
		return (-1);
	}
	b->rem -= dlen;
	b->len += dlen;
	b->data += dlen;

	return (0);
}

/*
 * Opposite of sbuff_advance().
 */
static __inline__ int
sbuff_retreat(struct sbuff *b, size_t dlen)
{
	if (dlen > b->len) {
		return (-1);
	}
	b->rem += dlen;
	b->len -= dlen;
	b->data -= dlen;

	return (0);
}

static __inline__ void *
sbuff_pull(struct sbuff *b, size_t dlen)
{
	void *d = NULL;

	if (dlen <= b->len) {
		d = b->data;
		b->data += dlen;
		b->rem -= dlen;
		b->len -= dlen;
	}

	return (d);
}

static __inline__ void *
sbuff_data(struct sbuff *b)
{
	return (b->data);
}

static __inline__ void
sbuff_reset(struct sbuff *b)
{
	b->data = b->head;
	b->rem = b->truesize;
	b->len = 0;
}

static __inline__ void
sbuff_reset_to(struct sbuff *b, int to_len)
{
	int d = to_len - b->len;

	if (d <= 0) {
		return;
	}
	b->data -= d;
	b->rem += d;
	b->len += d;
}

#endif	/* _LIB_SBUFF_H */
