#ifndef	_L2TRIGGERS_H
#define	_L2TRIGGERS_H

#include <stdint.h>

#define	MNET_DEF_L2TRIGGER_PORT	4242

#define	L2TRIGGER_LU	1 /* Link Up */
#define	L2TRIGGER_LD	2
#define	L2TRIGGER_ST	3
#define	L2TRIGGER_TT	4
#define	L2TRIGGER_MT	5
#define	L2TRIGGER_TTLU	6
#define L2TRIGGER_APASSOC	7 /* AP association */
#define L2TRIGGER_APDISASSOC	8 /* AP disassociation */

#define	L2TRIGGER_SLEEP	100

#define	L2TRIGGER_MAX_CODE 8

struct l2trigger_msg {
	uint32_t	code;
	char		*iface;
	int		addr1len;
	int		addr2len;
	uint8_t		*addr1;
	uint8_t		*addr2;
	int		pktlen;
	uint8_t		*pkt;
};

typedef	void (*l2trigger_cb)(struct l2trigger_msg *, void *);

extern int libtrigger_init(uint16_t);
extern int libtrigger_recv(int);
extern int libtrigger_register(uint32_t, l2trigger_cb, void *);

#endif	/* _L2TRIGGERS_H */
