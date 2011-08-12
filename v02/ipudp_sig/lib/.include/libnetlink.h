#ifndef __LIBNETLINK_H__
#define __LIBNETLINK_H__ 1

#include <netinet/in.h>
#include <pthread.h>
#include <sys/socket.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/uio.h>

#include <list.h>

struct rtnl_handle
{
	int			fd;
	struct sockaddr_nl	local;
	struct sockaddr_nl	peer;
	__u32			seq;
	__u32			dump;
	pthread_mutex_t		lock;
};

extern int rtnl_open(struct rtnl_handle *rth, unsigned subscriptions);
extern int rtnl_wilddump_request(struct rtnl_handle *rth, int fam, int type);
extern int rtnl_dump_request(struct rtnl_handle *rth, int type, void *req, int len);
extern int rtnl_dump_filter(struct rtnl_handle *rth,
			    int (*filter)(struct sockaddr_nl *, struct nlmsghdr *n, void *),
			    void *arg1,
			    int (*junk)(struct sockaddr_nl *,struct nlmsghdr *n, void *),
			    void *arg2);
extern int rtnl_talk(struct rtnl_handle *rtnl, struct nlmsghdr *n, pid_t peer,
		     unsigned groups, struct nlmsghdr *answer,
		     int (*junk)(struct sockaddr_nl *,struct nlmsghdr *n, void *),
		     void *jarg);
extern int rtnl_send(struct rtnl_handle *rth, char *buf, int);


extern int addattr32(struct nlmsghdr *n, int maxlen, int type, __u32 data);
extern int addattr_l(struct nlmsghdr *n, int maxlen, int type, void *data, int alen);
extern int rta_addattr32(struct rtattr *rta, int maxlen, int type, __u32 data);
extern int rta_addattr_l(struct rtattr *rta, int maxlen, int type, void *data, int alen);

extern int parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len);

extern int rtnl_listen(struct rtnl_handle *, int (*handler)(struct sockaddr_nl *,struct nlmsghdr *n, void *),
		       void *jarg);
extern int rtnl_recv(struct rtnl_handle *, int (*handler)(struct sockaddr_nl *,struct nlmsghdr *n, void *),
		       void *jarg);
extern int rtnl_from_file(FILE *, int (*handler)(struct sockaddr_nl *,struct nlmsghdr *n, void *),
		       void *jarg);

extern int libnetlink_init(void);

/* Extended netlink */
struct netlink_name {
	uint32_t		proto;
	int			nlen;
	uint8_t			name[128];
};

#define	SOL_NETLINK		269
#define	NETLINK_ASSIGN_PROTO	1

/* Convenience functions */

/*
 * Interface IP address constructs - basically a wrapper around
 * rtnetlink's address dump / event capabilities.
 */
struct nl_ifaddr {
	struct ifaddrmsg	*ifm;
	struct ifa_cacheinfo	*ci;
	union {
		struct in6_addr	a6;
		struct in_addr	a4;
	} addr_u;
#define	ift_addr6	addr_u.a6
#define	ift_addr4	addr_u.a4
};

/*
 * Callback structure for notification of IP address events.
 * The callback should return 1 if it wishes to be deregistered,
 * 0 otherwise. Event types are RTM_NEWADDR and RTM_DELADDR.
 */
struct ifaddr_event_cb {
	struct list_head	list;
	int			(*cb)(struct nl_ifaddr *, int, void *);
	void			*cookie;
};

extern int ifaddr_dump(struct ifaddr_event_cb *, struct rtnl_handle *);
extern void ifaddr_event_register(struct ifaddr_event_cb *);
extern void ifaddr_event_unregister(struct ifaddr_event_cb *);
extern void ifaddr_recv(struct rtnl_handle *rth);
extern int ifaddr_rtnl_open(struct rtnl_handle *);

/* Other convenience functions */
extern int neigh_add(struct rtnl_handle *, int, void *, size_t, uint8_t *,
    size_t, int, int, uint32_t, uint8_t);
extern int neigh_del(struct rtnl_handle *, int, void *, size_t, int, int);
extern int neigh_get(struct rtnl_handle *, int, void *, size_t , int *,
    uint8_t *, size_t *, uint16_t *);
extern int rtnl_addr_add(struct rtnl_handle *, struct ifaddrmsg *, void *,
    int);
extern int rtnl_addr_del(struct rtnl_handle *, struct ifaddrmsg *, void *,
    int);
extern int rtnl_route_add(struct rtnl_handle *, struct rtmsg *, int, void *,
    int, void *, int, void *, int, int);
extern int rtnl_route_del(struct rtnl_handle *, struct rtmsg *, int, void *,
    int, void *, int, void *, int, int);
extern int rtnl_get_route(struct rtnl_handle *, int, void *, int,
    void *, int, int);
extern int rtnl_get_saddr(struct rtnl_handle *, int, void *, int,
    void *, int, int *);
extern int nl_talk(int, int, struct iovec *, int, uint32_t, int, int);
extern int nl_talk2(int, int, struct iovec *, int, void *, int, uint32_t,
    int, int);
extern int rtnl_get_rtinfo(struct rtnl_handle *, int, void *, int, void *,
    int, int, struct rtattr *[]);

#endif /* __LIBNETLINK_H__ */

