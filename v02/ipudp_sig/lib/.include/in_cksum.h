/* in_cksum.h
 * Declaration of  Internet checksum routine.
 *
 * $Id: in_cksum.h,v 1.1.1.1 2005/05/27 22:17:59 root Exp $
 */

#include <stdint.h>

typedef struct {
	const uint8_t	*ptr;
	int		len;
} vec_t;

extern int in_cksum(const vec_t *vec, int veclen);
