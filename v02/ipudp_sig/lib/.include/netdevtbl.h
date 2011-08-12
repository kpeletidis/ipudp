#ifndef	_LIBNETDEV_H
#define	_LIBNETDEV_H

#include <stdint.h>
#include <hashtbl.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <linux/types.h>
#include <linux/rtnetlink.h>
#include <libnetlink.h>

#define	MAXL2ADDRLEN		16
#define	NETDEVTBL_HASH_SIZE	7

struct netdev_ent {
	htbl_item_t		hitm;
	int			index;
	int			media_type;
	uint8_t			l2addr[MAXL2ADDRLEN];
	int			l2len;
	int			mtu;
	uint32_t		flags;
	char			name[IFNAMSIZ];
};

struct netdev_tbl {
	/* public fields */
	struct rtnl_handle	*rth;
	int			(*filter_type)(uint16_t);
	/* private fields */
	htbl_t			*tbl;
	pthread_mutex_t		tbl_lock;
	struct list_head 	event_cbs;
	pthread_mutex_t		event_lock;
};

/*
 * Callback structure for notification of link events.
 * The callback should return 1 if it wishes to be deregistered,
 * 0 otherwise.
 */
struct netdevtbl_event_cb {
	struct list_head	list;
	int			(*cb)(struct netdev_tbl *, struct netdev_ent *,
				      int, struct nlmsghdr *, struct rtattr **,
				      uint32_t, void *);
	void			*cookie;
};

/* Events */
#define	NETDEVTBL_ADD	0
#define	NETDEVTBL_REM	1
#define	NETDEVTBL_UPD	2

extern void netdevtbl_event_register(struct netdev_tbl *,
    struct netdevtbl_event_cb *);
extern void netdevtbl_event_unregister(struct netdev_tbl *,
    struct netdevtbl_event_cb *);
extern void netdevtbl_exit(struct netdev_tbl *);
extern int netdevtbl_filter_non_ethertypes(uint16_t);
extern struct netdev_ent *netdevtbl_get(struct netdev_tbl *, int,
    struct netdev_ent *);
extern struct netdev_ent *netdevtbl_get_byl2(struct netdev_tbl *,
    struct netdev_ent *buf);
extern int netdevtbl_init(struct netdev_tbl *);
extern int netdevtbl_recv(struct netdev_tbl *);
extern void netdevtbl_walk(struct netdev_tbl *, walk_func, void *);

#endif	/* _LIBNETDEV_H */
