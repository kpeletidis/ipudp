#ifndef __KERNEL__
#define __KERNEL__
#endif

#ifndef MODULE
#define MODULE
#endif
/*XXX*/

#include "ipudp.h"

LIST_HEAD(ipudp_viface_list);
static DEFINE_SPINLOCK(ipudp_lock);


static ipudp_data *ipudp;
static int __ipudp_init_priv_data(ipudp_dev_priv *);
static void  ipudp_clean_priv(ipudp_dev_priv *);
void ipudp_list_tsa_flush(ipudp_dev_priv *);
void ipudp_list_tun_flush(ipudp_dev_priv *);


static const char banner[] __initconst =
	KERN_INFO "Tunneling - IP over IP/UDP - module\n";

static void __conf_init(void) {
	ipudp->conf.max_dev_num = IPUDP_CONF_MAX_DEV;
	ipudp->conf.default_mode = MODE_FIXED; 
	ipudp->conf.default_af_out = IPV4;
}

struct list_head __inline * ipudp_get_viface_list(void) {	
	return ipudp->viface_list;
}

int __inline ipudp_get_viface_count(void) {
	return ipudp->viface_count;
}

ipudp_dev_priv * 
ipudp_get_priv(char *name) {
	ipudp_dev * p;
	struct net_device *d;
	list_for_each_entry_rcu(p, ipudp->viface_list, list) {
		if (!strcmp(name, p->dev->name)) {
			d = p->dev;
			return netdev_priv(d);
		}
	}

	return NULL;

}

static void 
__list_ipudp_dev_init(void) {
	ipudp->viface_list = &ipudp_viface_list;
	ipudp->viface_count = 0;
}


static ipudp_dev * 
__list_ipudp_dev_locate_by_name(char *name) {
	ipudp_dev * p;

	list_for_each_entry_rcu(p, ipudp->viface_list, list) {
		if (!strcmp(name, p->dev->name)) {
			return p;
		}
	}
	return NULL;
}

static void 
__list_dev_add(struct net_device * dev){
	ipudp_dev * p;

	p = kzalloc(sizeof(ipudp_dev), GFP_KERNEL);
	p->dev = dev;
	spin_lock_bh(&ipudp_lock);	
	list_add_rcu(&(p->list), ipudp->viface_list);
	spin_unlock_bh(&ipudp_lock);	
	ipudp->viface_count ++;	
}

void 
ipudp_list_tun_add(ipudp_dev_priv *p, ipudp_tun_params *tun){ 
	ipudp_list_tun_item *item, *t;
	
	if((p->params.mode == MODE_FIXED) && (!(list_empty(&(p->list_tun))))) {
		t = (ipudp_list_tun_item *)p->list_tun.next;
		spin_lock_bh(&ipudp_lock);
		list_del_rcu(&(t->list));
		spin_unlock_bh(&ipudp_lock);
		synchronize_rcu();
		kfree(t);
	}

	item = (ipudp_list_tun_item *)kmalloc(sizeof(*item), GFP_KERNEL);
	memcpy(&(item->tun), tun, sizeof(*tun));

	spin_lock_bh(&ipudp_lock);
	list_add_rcu(&(item->list), &(p->list_tun));
	spin_unlock_bh(&ipudp_lock);
	p->tun_count++;
}

void 
ipudp_list_tun_del(ipudp_dev_priv *p, ipudp_tun_params *tun) {
	//TODO	
	return;
}

void
ipudp_list_tun_flush(ipudp_dev_priv *priv) {
	ipudp_list_tun_item *p,*q;
	
	list_for_each_entry_safe(p, q, &(priv->list_tun), list) {
		list_del_rcu(&(p->list));
		synchronize_rcu();
		kfree(p);
	}

	priv->tun_count = 0;
}

void 
ipudp_list_tsa_add(ipudp_dev_priv *p, ipudp_tsa_params *tsa) {
	ipudp_list_tsa_item *item;
	
	item = (ipudp_list_tsa_item *)kmalloc(sizeof(*item), GFP_KERNEL);
	memcpy(&(item->tsa), tsa, sizeof(*tsa));
	spin_lock_bh(&ipudp_lock);
	list_add_rcu(&(item->list), &(p->list_tsa));
	spin_unlock_bh(&ipudp_lock);
	p->tsa_count ++;
}

void 
ipudp_list_tsa_del(ipudp_dev_priv *p, ipudp_tsa_params *tsa) {
	//TODO	
	return;
}

void 
ipudp_list_tsa_flush(ipudp_dev_priv *priv) {
	ipudp_list_tsa_item *p,*q;
	
	list_for_each_entry_safe(p, q, &(priv->list_tsa), list) {
		list_del_rcu(&(p->list));
		sock_release(p->tsa.sock);
		synchronize_rcu();
                kfree(p);
	}
	priv->tsa_count = 0;
	return;
}

static void 
__list_viface_del(ipudp_dev *viface) {
	list_del_rcu(&(viface->list));					
}

static void 
ipudp_tunnel_uninit(struct net_device *dev) {		
	ipudp_dev_priv *priv = netdev_priv(dev);
	
	ipudp_clean_priv(priv);
}

static void 
__list_dev_flush(void) {
	ipudp_dev *p,*q;

	list_for_each_entry_safe(p, q, ipudp->viface_list, list) {
		unregister_netdev(p->dev);
		list_del(&p->list);
		kfree(p);
	}
}

int 
ipudp_del_viface(ipudp_viface_params *p) {			
	ipudp_dev *viface; 
	struct net_device *dev;

	spin_lock_bh(&ipudp_lock);
	list_for_each_entry(viface, ipudp->viface_list, list) {
		if (!strcmp(p->name, viface->dev->name)) {
			dev = viface->dev;
			goto found;
		}
	}

	
	spin_unlock_bh(&ipudp_lock);
	return IPUDP_ERR_DEV_NOT_FOUND;

found:
	__list_viface_del(viface);
	
	spin_unlock_bh(&ipudp_lock);
	
	synchronize_rcu();
	kfree(viface);

	unregister_netdev(dev);
	return IPUDP_OK;

}

unsigned int 
ipudp_tsa6_rcv(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in,
			  const struct net_device *out, int (*okfn)(struct sk_buff*)) {
	/*TODO*/
	return NF_ACCEPT;
}


unsigned int 
ipudp_tsa4_rcv(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in,
			  const struct net_device *out, int (*okfn)(struct sk_buff*)) {

	struct iphdr * iph;
	struct udphdr * udph;
	ipudp_dev *p;
	ipudp_dev_priv *priv;
	ipudp_list_tsa_item *tsa_i;
	
	iph = (struct iphdr *)skb->data;	
	if (iph->protocol != IPPROTO_UDP) return NF_ACCEPT;

	udph = (struct udphdr *)(skb->data + (iph->ihl*4));

	rcu_read_lock();
	list_for_each_entry_rcu(p, ipudp->viface_list, list) {
		priv = netdev_priv(p->dev);
		list_for_each_entry_rcu(tsa_i, &(priv->list_tsa), list) {
			if ((tsa_i->tsa.u.v4addr == iph->daddr) && 
					(tsa_i->tsa.port == udph->dest)) {

				priv->tun_recv(skb, p->dev);
				goto done;
			}
		}
	}
	rcu_read_unlock();

	return NF_ACCEPT;
done:
	rcu_read_unlock();
	return NF_DROP;
}

static int
ipudp_tunnel_xmit(struct sk_buff *skb, struct net_device *dev) {
	struct ipudp_dev_priv * p;	
	ipudp_tun_params *tun = NULL;

	
	p = netdev_priv(dev);

	//XXX Lock?
	rcu_read_lock();
	
	if (!(tun = p->fw_lookup(skb, p))) {
		dev_kfree_skb(skb);
		dev->stats.tx_dropped++;
		dev->stats.tx_errors++;
		goto done;
	}
	p->tun_xmit(skb, tun, dev);

done:
	rcu_read_unlock();	
	return NETDEV_TX_OK;
}

static int 
ipudp_tunnel_change_mtu(struct net_device *dev, int new_mtu)
{
	//TODO	
	//XXX cosnider ipv6 or v6 XXX
	if (new_mtu < 68 || new_mtu > ETH_DATA_LEN - 
		sizeof(struct iphdr) - sizeof(struct udphdr))
	
	return -EINVAL;
	dev->mtu = new_mtu;
	return 0;
}

static const struct 
net_device_ops ipudp_netdev_ops = {
	.ndo_uninit     = ipudp_tunnel_uninit,
	.ndo_start_xmit = ipudp_tunnel_xmit,
	.ndo_change_mtu = ipudp_tunnel_change_mtu,
};

static void 
ipudp_tunnel_setup(struct net_device *dev)
{
	dev->netdev_ops         = &ipudp_netdev_ops;
	dev->destructor         = free_netdev;
	dev->type               = ARPHRD_TUNNEL;
	dev->hard_header_len    = LL_MAX_HEADER + sizeof(struct iphdr) 
				+ sizeof(struct udphdr);
		
	/*default starting MTU - it might be changed 
	everytime we add a real interface under ipudp control*/
	//XXX TODO cosnider ipv6 or v6 XXX
	dev->mtu                = ETH_DATA_LEN - sizeof(struct iphdr) 
					- sizeof(struct udphdr);

	dev->flags              = IFF_NOARP;
	dev->iflink             = 0;
	dev->addr_len           = 4;
	dev->features           |= NETIF_F_NETNS_LOCAL;
}

static int 
ipudp_nf_init(struct nf_hook_ops *p) {
	int err;

	p->hook 	= ipudp_tsa4_rcv;
	p->pf	= PF_INET;
	p->hooknum	= NF_INET_PRE_ROUTING;
	p->priority	= NF_IP_PRI_FIRST;
        
	if ((err = nf_register_hook(p)))
		kfree(p);

	return err;
}

static int 
ipudp_nf6_init(struct nf_hook_ops *p) {
	int err;

	p->hook 	= ipudp_tsa6_rcv;
	p->pf	= PF_INET6;
	p->hooknum	= NF_INET_PRE_ROUTING;
	p->priority	= NF_IP_PRI_FIRST;
        
	if ((err = nf_register_hook(p)))
		kfree(p);

	//TODO register IPV6 hook
	return err;
}

static int __inline 
new_dev_not_allowed(void) {
	if ((ipudp->viface_count) < (ipudp->conf.max_dev_num))
		return 0;
	return -1;
}

static void 
ipudp_clean_priv(ipudp_dev_priv * p) {
	/* free tun list */
	ipudp_list_tun_flush(p);
	/* free tsa list */
	ipudp_list_tsa_flush(p);

	return;
}

ipudp_tun_params * 
ipudp_fixed_out_tun(struct sk_buff *buff, void *priv) {
	ipudp_list_tun_item *item;
	struct list_head l;

	if ( ((ipudp_dev_priv *)priv)->tun_count == 0 )
		return NULL;

	l = ((ipudp_dev_priv *)priv)->list_tun ;
	item = (ipudp_list_tun_item *)rcu_dereference(l.next);

	return (ipudp_tun_params *)&(item->tun);
}

__u16 __udp_cheksum(struct iphdr *iph, struct udphdr *udph) {
	__wsum	csum;

	csum = csum_partial(udph, ntohs(udph->len), 0);
	return csum_tcpudp_magic(iph->saddr, iph->daddr, ntohs(udph->len), IPPROTO_UDP, csum);
}

void
ipudp_tun4_xmit(struct sk_buff *skb, ipudp_tun_params *tun, struct net_device *dev) {
	
#if 0
	printk("ipudp: dev tun4 xmit\n");
	printk("ipudp: outgoing tunnel: \n");
	if (tun->af == IPV4) {
		printk("daddr: %d.%d.%d.%d", NIPQUAD(tun->u.v4p.dest));
		printk("daddr: %d.%d.%d.%d", NIPQUAD(tun->u.v4p.src));
	}
	printk("sport: %d ", (int)ntohs(tun->srcport));
	printk("dport: %d \n", (int)ntohs(tun->destport));
#endif
	struct iphdr *iph_in =(struct iphdr *) skb->data;
	struct iphdr *iph;
	struct udphdr *udph;
	struct sk_buff *new_skb; 
	struct rtable *rt;
	struct netdev_queue *txq = netdev_get_tx_queue(dev, 0);
	struct net_device_stats *stats = &dev->stats;
	int err;

	
	if (skb->protocol != htons(ETH_P_IP))
		goto tx_error;

	if (skb->len > dev->mtu) {
		stats->tx_dropped++;
		goto tx_error;
	}

	{	
		struct flowi fl = {
			.oif = tun->dev_idx,
			.nl_u = {
				.ip4_u = {
					.daddr 	= tun->u.v4p.dest,
					.saddr 	= tun->u.v4p.src,
					.tos 	= RT_TOS(iph_in->tos)
				}
			},
			.proto 	= IPPROTO_IP
		};

		if (ip_route_output_key(dev_net(dev), &rt, &fl)) {
			stats->tx_carrier_errors++;
			goto tx_error;
		}
	}

	if (rt->u.dst.dev == dev) {
		stats->collisions++;
		ip_rt_put(rt);
		goto tx_error;
	}

	if (skb_headroom(skb) < LL_RESERVED_SPACE(rt->u.dst.dev) + IPUDP4_HDR_LEN 
			|| skb_shared(skb) || (skb_cloned(skb) && !skb_clone_writable(skb, 0))) {
		new_skb = skb_realloc_headroom(skb, IPUDP4_HDR_LEN);
		if (!new_skb) {
			stats->tx_dropped++;
			ip_rt_put(rt);
			goto tx_error;
		}

		if (skb->sk) 
			skb_set_owner_w(new_skb, skb->sk);

		dev_kfree_skb(skb);
		skb = new_skb;
		iph_in = ip_hdr(skb);
	}

	skb_push(skb, IPUDP4_HDR_LEN);
	skb_reset_network_header(skb);

	memset(&(IPCB(skb)->opt), 0, sizeof(IPCB(skb)->opt));
	//XXX check
	IPCB(skb)->flags &= ~(IPSKB_XFRM_TUNNEL_SIZE | IPSKB_XFRM_TRANSFORMED | IPSKB_REROUTED);
	skb_dst_drop(skb);
	skb_dst_set(skb, &rt->u.dst);

	//push ipudp tunnel header
	{
		__u16 cs;	
		//IP
 		iph		= (struct iphdr *)skb->data;
		iph->version	= 4;
		iph->ihl	= sizeof(struct iphdr)>>2;
		iph->frag_off 	= htons(IP_DF); //XXX
		iph->protocol	= IPPROTO_UDP;
		iph->tos	= 0;
		iph->saddr	= rt->rt_src;
		iph->daddr 	= rt->rt_dst;
		iph->tot_len 	= htons(ntohs(iph_in->tot_len) + IPUDP4_HDR_LEN);
		iph->ttl	= iph_in->ttl;
		iph->check 	= 0;
		//UDP
		udph 		= (struct udphdr *)(skb->data + 20);
		udph->source	= tun->srcport;
		udph->dest	= tun->destport;
		udph->len 	= htons(ntohs(iph_in->tot_len) + 8);
		udph->check	= 0;

		ip_select_ident(ip_hdr(skb), &rt->u.dst, NULL);
		skb->ip_summed = CHECKSUM_NONE; //it will be computed later on
		cs = __udp_cheksum(iph, udph);
		udph->check = cs;
	}

	nf_reset(skb);
	skb->mark = tun->mark;
#if 0
	printk("ipudp: outgoing packet\n");
	printk("daddr: %d.%d.%d.%d", NIPQUAD(tun->u.v4p.dest));
		printk("daddr: %d.%d.%d.%d", NIPQUAD(tun->u.v4p.src));
	printk("sport: %d ", (int)ntohs(tun->srcport));
	printk("dport: %d \n", (int)ntohs(tun->destport));
#endif	
	dev->stats.tx_packets++;
	dev->stats.tx_bytes += skb->len;
	err = ip_local_out(skb);

	if (likely(net_xmit_eval(err) == 0)) {
		txq->tx_bytes += skb->len;
		txq->tx_packets++;
	} else {
		stats->tx_errors++;
		stats->tx_aborted_errors++;
	}

	return;	

tx_error:
	stats->tx_errors++;
	dev_kfree_skb(skb);
}

void 
ipudp_tun6_xmit(struct sk_buff *buf, ipudp_tun_params *tun, struct net_device *dev) {
	//TODo
	return;
}

void
ipudp_tun4_recv(struct sk_buff *skb, struct net_device *dev) {
		
	/* IP UDP CHECKSUM verification */

#if 0
	/* continue NETFILTER HOOK */
	secpath_reset(skb);
	dev->stats.rx_packets++;
	dev->stats.rx_bytes += skb->len;
	skb_pull(skb, IPUDP4_HDR_LEN);
	skb_reset_network_header(skb);

	skb->dev = dev;
	skb_dst_drop(skb);
	nf_reset(skb);
#endif

	struct sk_buff *new_skb = skb_clone(skb, GFP_ATOMIC);
	
	secpath_reset(new_skb);
	//new_skb->mac_header = new_skb->network_header;
	skb_pull(new_skb, IPUDP4_HDR_LEN);
	//skb_reset_network_header(new_skb);
	new_skb->protocol = htons(ETH_P_IP);
	new_skb->pkt_type = PACKET_HOST;
	
	/* Reschedule NET_RX softirq */
	dev->stats.rx_packets++;
	dev->stats.rx_bytes += new_skb->len;
	
	new_skb->dev = dev;
	skb_dst_drop(new_skb);
	nf_reset(new_skb);
	netif_rx(new_skb);
}

void
ipudp_tun6_recv(struct sk_buff *buf, struct net_device *dev) {
	//TODO
	return;
}

static int
__ipudp_init_priv_data(ipudp_dev_priv *p) {
	int ret;

	switch(p->params.mode) {
		case MODE_FIXED:
			p->fw_table = NULL;
			p->fw_lookup = ipudp_fixed_out_tun;
			p->fw_update = NULL;
			 	if (p->params.af_out == IPV4) {
				p->tun_xmit = ipudp_tun4_xmit;
				p->tun_recv = ipudp_tun4_recv;
			}
			else if (p->params.af_out == IPV6){
				p->tun_xmit = ipudp_tun6_xmit;
				p->tun_recv = ipudp_tun6_recv;
			}
			else {
				ret = IPUDP_BAD_PARAMS;
				goto done;
			}
			break;
		default:
			ret = IPUDP_BAD_PARAMS;
			goto done;
			break;
	}
	//init tun list
	p->list_tun.prev = &p->list_tun;
	p->list_tun.next = &p->list_tun;
	//init tsa list
	p->list_tsa.prev = &p->list_tsa;
	p->list_tsa.next = &p->list_tsa;

	p->max_tun = IPUDP_CONF_MAX_TUN;
	p->max_tsa = IPUDP_CONF_MAX_TSA;

	return IPUDP_OK;
done:
	return ret;
}

/*
static int
__get_new_tid(struct list_head *l) {
	ipudp_list_tun_item *p;
	int i = 1; //XXX from 1

	list_for_each_entry(p, l, list) {
		if ((p->tid != i)) { 
			return i;
		}
	}
	return i;
}
*/

static int
__tun_addr_is_null(int len, __u8 *addr) {
	int i;

	for (i = 0; i < len; i++) {
		if (addr[i] != 0) return 0;
	}

	return 1;
}

static int 
__tun_src_is_null(ipudp_tun_params *p) {
	int vers = p->af;
	void *addr;
	int len;

	if (vers == IPV4) {
		addr = &(p->u.v4p.src);
		len = 4;
	}
	else if (vers == IPV6) {
		addr = p->u.v6p.src;
		len = 16;
	}
	else //can't happen 
	return -1;

	return __tun_addr_is_null(len, addr);  
}

static int 
__tun_dst_is_null(ipudp_tun_params *p) {
	int vers = p->af;
	void *addr;
	int len;

	if (vers == IPV4) {
		addr = &(p->u.v4p.dest);
		len = 4;
	}
	else if (vers == IPV6) {
		addr = p->u.v6p.dest;
		len = 16;
	}
	else //cant happen 
		return -1;
	
	return __tun_addr_is_null(len, addr);
}

/* reserve listening port if it is given otherwise 
pick a free port and reserve it*/
static int 
__tsa_reserve_port(ipudp_tun_params *p, ipudp_tsa_params *tsa){
	struct socket *sock;
	int err = IPUDP_OK;
	struct net_device * dev = NULL;
	int addr_len;
	void *addr_ptr = NULL;

	if (p->dev_idx) {
		tsa->dev_idx = p->dev_idx;
		dev = dev_get_by_index(&init_net, p->dev_idx);
		if(!dev) {
			err = IPUDP_ERR_TUN_BAD_PARAMS;
			goto err_return;
		}	
	}

	switch(p->af) {
		case IPV4: {
			struct sockaddr_in addr;

			addr_ptr = &addr;
			addr_len = sizeof(addr);
			//XXX TODO check if tsa already in the list

			memset(&addr, 0, sizeof(struct sockaddr));
			addr.sin_family = AF_INET;
			addr.sin_addr.s_addr = p->u.v4p.src; //XXX if 0 --> add_any
			addr.sin_port = p->srcport;
		
			if (sock_create(addr.sin_family, SOCK_DGRAM, 
						IPPROTO_UDP, &sock) < 0) {
				err = IPUDP_ERR_TSA_SOCK_CREATE;
				goto err_return;
			}
		
			tsa->u.v4addr = p->u.v4p.src;
			break;
		}

		case IPV6: {
			struct sockaddr_in6 addr;	

			addr_ptr = &addr;
			addr_len = sizeof(addr);
			//XXX TODO check if tsa already in the list
		
			memset(&addr, 0, sizeof(struct sockaddr_in6));
			addr.sin6_family = AF_INET6;
			memcpy(&addr.sin6_addr, &p->u.v6p.src, 
					sizeof(struct in6_addr)); //XXX if all 0 --> addr_any
			addr.sin6_port = p->srcport;
		
			if (sock_create(addr.sin6_family, SOCK_DGRAM, 
						IPPROTO_UDP, &sock) < 0) {
				err = IPUDP_ERR_TSA_SOCK_CREATE;
				goto err_return;
			}

			memcpy(&tsa->u.v6addr, &addr.sin6_addr, 
						sizeof(struct in6_addr));
			break;
		}
		default:
			err = IPUDP_ERR_TUN_BAD_PARAMS;
			goto err_return;
	}

	if(sock->ops->bind(sock, (struct sockaddr *)addr_ptr, addr_len) < 0){
		err = IPUDP_ERR_TSA_SOCK_BIND;
		goto err_free_sock;
	}
	//XXX TODO check if the bind failed because already bound
	//by another tunnel - should be enough to check if the TSA
	//is already in the list (above). if TSA is already bound 
	//for the same iface, no problem. 
	
	tsa->sock = sock;
	tsa->af = p->af;
	tsa->port = p->srcport; 

	return IPUDP_OK;

err_free_sock:	
	kfree(sock);
err_return:
	return err;	
}


static int 
__ipudp_create_and_add_tsa(ipudp_dev_priv *p, ipudp_tun_params *tun) {
	int ret;
	ipudp_tsa_params tsa;
	ipudp_list_tsa_item *t;

	memset(&tsa,0,sizeof(tsa));
	
	if (p->tsa_count == p->max_tsa)	
		return IPUDP_ERR_TSA_MAX;

	if ((ret = __tsa_reserve_port(tun, &tsa)))
		return ret;
	
	if((p->params.mode == MODE_FIXED) && (!(list_empty(&(p->list_tsa))))) {
		t = (ipudp_list_tsa_item *)p->list_tsa.next;
		spin_lock_bh(&ipudp_lock);
		list_del_rcu(&(t->list));
		spin_unlock_bh(&ipudp_lock);
		synchronize_rcu();
		kfree(t);
	}

	ipudp_list_tsa_add(p, &tsa);

#if 0	
	printk("ipudp_create_tsa: af %d dev_idx %d port %d",
		tsa.af, tsa.dev_idx, (int)(ntohs(tsa.port)));

	if (tun->af == IPV4)
		printk("saddr: %d.%d.%d.%d\n", NIPQUAD(tsa.u.v4addr));
#endif
	return IPUDP_OK;
}

int 
ipudp_del_tsa(ipudp_tsa_params *tsa) {
	/*	ipudp_tsa_item *p,*q;
	
	for_each_entry_safe();
	listdel(p)
	kfree(p->sock)
	kfree(p)
	*/	
	return 0;
}

int
ipudp_bind_tunnel(ipudp_viface_params *p, ipudp_tun_params *tun) {
	int ret;
	ipudp_dev *viface;
	struct ipudp_dev_priv *priv;
	struct net_device *dev;

	rcu_read_lock();
	viface =__list_ipudp_dev_locate_by_name(p->name);
	if (!viface) {
		ret = IPUDP_ERR_DEV_NOT_FOUND;
		rcu_read_unlock();
		goto err_ret;
	}
	dev = rcu_dereference(viface->dev);

	priv = (ipudp_dev_priv *)netdev_priv(dev);	

	if (priv->tun_count == priv->max_tun) {	
		ret = IPUDP_ERR_TUN_MAX;
		goto err_ret;
	}

	if (priv->params.mode != MODE_FIXED) {
		//tun->tid = __get_new_tid(&(priv->list_tun));TODO
		ret = IPUDP_ERR_TUN_BAD_PARAMS; //TODO
		goto err_ret;
	}	
	rcu_read_unlock();
	
	if(  (( __tun_src_is_null(tun)) && (!(tun->dev_idx)))
		|| __tun_dst_is_null(tun) || (!(tun->destport)) 
						|| (!(tun->srcport)) )
	{
		ret = IPUDP_ERR_TUN_BAD_PARAMS;
		goto err_ret;
	}

	/* reserve listening port and add tsa to list */
	if ((ret = __ipudp_create_and_add_tsa(priv, tun))) 
		goto err_ret;

	/* add tunnel to list */
	ipudp_list_tun_add(priv, tun);

	return IPUDP_OK;
	
err_ret:
	return ret;
}

int 
ipudp_add_viface(ipudp_viface_params * p) {
	int err;
	struct net_device *dev;
	struct ipudp_dev_priv * ipudp_priv;

	
	if (new_dev_not_allowed()) {
		err = IPUDP_ERR_DEV_MAX;
		goto err_dev_alloc;
	}

	//TODO copy viface_params

	if (!strlen(p->name))
		dev = alloc_netdev(sizeof(*ipudp_priv),"ipudp%d",
					ipudp_tunnel_setup);
	else	
		dev = alloc_netdev(sizeof(*ipudp_priv),p->name,
					ipudp_tunnel_setup);

	if (!dev) {
		err = IPUDP_ERR_DEV_ALLOC;
		goto err_dev_alloc;
	}
	
	//find first free index %d in dev->name="ipudp%d"
	if (!strlen(p->name)){
		if (dev_alloc_name(dev, dev->name) < 0){
			err = IPUDP_ERR_DEV_NAME;
			goto err_alloc_name;
		}
		strcpy(p->name, dev->name);
	}
	/* set ipudp dev private data */
	ipudp_priv = netdev_priv(dev);
	
	if (!p->mode)
		p->mode = ipudp->conf.default_mode;

	if (!p->af_out)
		p->af_out = ipudp->conf.default_af_out;

	//copy ipudp private dev data
	memcpy(&ipudp_priv->params, p, sizeof(*p));
	
	err = __ipudp_init_priv_data(ipudp_priv);
	if (err)
		goto err_init_priv;	

	//register net device
	if (register_netdev(dev)) {
		err = IPUDP_ERR_DEV_REG;
		goto err_reg_dev;
	}

	//add dev to internal list 
	////XXX maybe useless
	__list_dev_add(dev); 

	
	return IPUDP_OK;

err_reg_dev:
	free_netdev(dev);
err_init_priv:
	ipudp_clean_priv(ipudp_priv);
err_alloc_name:
err_dev_alloc:
	spin_unlock_bh(&ipudp_lock);
	return err;

}

static int __init ipudp_init(void) {
	int err = 0;
	struct nf_hook_ops *p, *q;

	printk(banner);

	ipudp = kzalloc(sizeof(ipudp_data), GFP_KERNEL);
	
	__conf_init();
	__list_ipudp_dev_init();
	
	if ((err = ipudp_genl_register())) 
		goto err_genl_register;

	//IPv4 hook
	p = kzalloc(sizeof(struct nf_hook_ops), GFP_KERNEL);
	if ((err = ipudp_nf_init(p)))
		goto err_nf_hook;

	ipudp->nf_hook_ops_in = p;
	
	//IPv6 hook
	q = kzalloc(sizeof(struct nf_hook_ops), GFP_KERNEL);
	if ((err = ipudp_nf6_init(q)))
		goto err_nf6_hook;

	ipudp->nf_hook_ops_6_in = q;
	return 0;

err_nf6_hook:
	kfree(q);
err_nf_hook:
	kfree(p);
err_genl_register:
	kfree(ipudp);
	return err;
}

static void __exit ipudp_fini(void) {

	__list_dev_flush();
	nf_unregister_hook(ipudp->nf_hook_ops_in);
	ipudp_genl_unregister();
	kfree(ipudp->nf_hook_ops_in);
	kfree(ipudp);
	printk(KERN_INFO "UMPT module unloaded\n");
}

module_init(ipudp_init);
module_exit(ipudp_fini);
MODULE_LICENSE("GPL");
