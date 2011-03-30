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
void ipudp_list_rules_flush(ipudp_dev_priv *);
void ipudp_list_tun_flush(ipudp_dev_priv *);

ipudp_list_tsa_item *__tsa_already_in_list(ipudp_dev_priv *, ipudp_tun_params *);

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

	list_for_each_entry(p, ipudp->viface_list, list) {
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
	ipudp->viface_count ++;	
	spin_unlock_bh(&ipudp_lock);	
}

void
ipudp_list_tun_flush(ipudp_dev_priv *priv) {
	ipudp_list_tun_item *p,*q;
	list_for_each_entry_safe(p, q, &(priv->list_tun), list) {
		list_del(&(p->list));
		kfree(p);
	}

	priv->tun_count = 0;
}

void 
ipudp_list_tsa_flush(ipudp_dev_priv *priv) {
	ipudp_list_tsa_item *p,*q;
	
	list_for_each_entry_safe(p, q, &(priv->list_tsa), list) {
		list_del(&(p->list));
		sock_release(p->tsa.sock);
        kfree(p);
	}
	priv->tsa_count = 0;
	return;
}

void 
ipudp_list_rules_flush(ipudp_dev_priv *priv) {
	ipudp_rule_multi_v4 *p, *q;
	
	list_for_each_entry_safe(p, q, &(priv->list_tsa), list) {
		list_del(&(p->list));
        kfree(p);
	}

	return;
}

//delete tsa by inode number for the associated socket
int 
ipudp_del_tsa(ipudp_viface_params *p, ipudp_tsa_params *q){
	ipudp_dev *viface; 
	ipudp_list_tsa_item *item;
	struct ipudp_dev_priv *priv = NULL;

	spin_lock_bh(&ipudp_lock);
	list_for_each_entry(viface, ipudp->viface_list, list) {
		if (!strcmp(p->name, viface->dev->name)) {
			priv = netdev_priv(viface->dev);

			list_for_each_entry(item, &(priv->list_tsa), list) {
				if (q->ino == item->tsa.ino) {
					list_del_rcu(&(item->list));
					priv->tsa_count --;
					spin_unlock_bh(&ipudp_lock);	
					synchronize_rcu();
					sock_release(item->tsa.sock);
					kfree(item);
					return IPUDP_OK;
				}
			}
			spin_unlock_bh(&ipudp_lock);	
			return IPUDP_ERR_TUN_NOT_FOUND;
		}
	}
	
	spin_unlock_bh(&ipudp_lock);
	return IPUDP_ERR_DEV_NOT_FOUND;


	return IPUDP_OK;
}

int 
ipudp_add_tsa(ipudp_viface_params *viface, ipudp_tsa_params *tsa){
	//XXX TODO XXX
	return IPUDP_OK;
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
		list_del(&(p->list));
		unregister_netdev(p->dev);
		kfree(p);
	}
}


//XXX make general and call a callback to actually delete the rule TODO
int
ipudp_del_rule(ipudp_viface_params *p, ipudp_rule *rule) {
	ipudp_dev *viface;
	ipudp_dev_priv *priv;
	ipudp_rule *item;

	spin_lock_bh(&ipudp_lock);
	list_for_each_entry(viface, ipudp->viface_list, list) {
		if (!strcmp(p->name, viface->dev->name)) {
			priv = netdev_priv(viface->dev);
		
			if (priv->fw_rules == NULL) {	
					spin_unlock_bh(&ipudp_lock);	
					return IPUDP_ERR_RULE_NOT_SUPPORTED;
			}

			list_for_each_entry(item, (struct list_head *)priv->fw_rules, list) {
				if (rule->id == item->id){
					list_del_rcu(&item->list);
					priv->rule_count --;
					spin_unlock_bh(&ipudp_lock);
					synchronize_rcu();
					kfree(item);
					return IPUDP_OK;
				}
			}
			spin_unlock_bh(&ipudp_lock);	
			return IPUDP_ERR_RULE_NOT_FOUND;
		}
	}
	spin_unlock_bh(&ipudp_lock);
	return IPUDP_ERR_DEV_NOT_FOUND;
}

static void
__list_detach_rules_to_tun(struct ipudp_dev_priv *priv, __u32 tid) {
	ipudp_rule *rule;
	
	list_for_each_entry(rule, (struct list_head *)priv->fw_rules, list) {
		if (rule->tun_id == tid) {
			rule->tun = NULL;
			rule->tun_id = 0;
		}
	}
}

static void
__detach_rules_to_tun(struct ipudp_dev_priv *priv, __u32 tid) {
	if (priv->params.mode == MODE_MULTI_V4)
		__list_detach_rules_to_tun(priv, tid);
	else
		return;
}

// delete tunnel by tid
int
ipudp_del_tun(ipudp_viface_params *p, ipudp_tun_params *q) {
	ipudp_dev *viface; 
	ipudp_list_tun_item *item;
	ipudp_list_tsa_item *tsa_i;
	struct ipudp_dev_priv *priv = NULL;

	spin_lock_bh(&ipudp_lock);
	list_for_each_entry(viface, ipudp->viface_list, list) {
		if (!strcmp(p->name, viface->dev->name)) {
			priv = netdev_priv(viface->dev);

			list_for_each_entry(item, &(priv->list_tun), list) {
				if (q->tid == item->tun.tid) {
					//delete the tunnel
					list_del_rcu(&(item->list));
					priv->tun_count --;
					
					//delete the referenced tsa if no other
					//tunnel is referencing it
					tsa_i = __tsa_already_in_list(priv, &(item->tun));
					if (tsa_i) {
						if (tsa_i->tsa.ref_cnt == 1) {
							list_del_rcu(&(tsa_i->list));
							sock_release(tsa_i->tsa.sock);
							priv->tsa_count --;
						}
						else  {
							tsa_i->tsa.ref_cnt --;
							tsa_i = NULL;
						}
					}
					
					//detach all rules pointing to this tunnel
					//XXX not sure if it is better to automatically delete rules...
					__detach_rules_to_tun(priv, item->tun.tid);

					spin_unlock_bh(&ipudp_lock);	

					synchronize_rcu();
					kfree(item);
					if (tsa_i) {
						kfree(tsa_i);
					}
					return IPUDP_OK;
				}
			}
			spin_unlock_bh(&ipudp_lock);	
			return IPUDP_ERR_TUN_NOT_FOUND;
		}
	}
	
	spin_unlock_bh(&ipudp_lock);
	return IPUDP_ERR_DEV_NOT_FOUND;

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
	list_del_rcu(&(viface->list));
	ipudp->viface_count--;
	spin_unlock_bh(&ipudp_lock);	
	synchronize_rcu();
	kfree(viface);
	
	unregister_netdev(dev);

	return IPUDP_OK;
}

__u16 __udp6_cheksum(struct ipv6hdr *iph, struct udphdr *udph) {
	__wsum	csum;

	csum = csum_partial(udph, ntohs(udph->len), 0);
	return csum_ipv6_magic(&(iph->saddr), &(iph->daddr),
			ntohs(udph->len), IPPROTO_UDP, csum);
}

static int
ipudp_checksum6_ok(struct ipv6hdr *iph, struct udphdr *udph) {
	__u16 csum;

	csum = udph->check;	
	udph->check = 0;
	udph->check = __udp6_cheksum(iph, udph);

	if (csum != udph->check)
		return 0;

	return 1;
}

unsigned int 
ipudp_tsa6_rcv(unsigned int hooknum, struct sk_buff *skb, 
	const struct net_device *in, const struct net_device *out, 
					int (*okfn)(struct sk_buff*)) {
	struct ipv6hdr * iph;
	struct udphdr * udph;
	ipudp_dev *p;
	ipudp_dev_priv *priv;
	ipudp_list_tsa_item *tsa_i;
	struct in6_addr *addr;

	iph = ipv6_hdr(skb);

	/* for now, if there are options discard the packet */
	/* TODO maybe could be usefull to use options...*/
	/* XXX not sure if in the path some router can add any opt.
	if so, the packet shouldn't be discarded... CHECK IT */
	if (iph->nexthdr != IPPROTO_UDP) return NF_ACCEPT;

	udph = (struct udphdr *) ((__u8 *)iph + sizeof(*iph)); 

	rcu_read_lock();
	list_for_each_entry_rcu(p, ipudp->viface_list, list) {
		priv = netdev_priv(p->dev);
		if (priv->params.af_out == IPV6) {
			list_for_each_entry_rcu(tsa_i, &(priv->list_tsa), list){
				addr = (struct in6_addr *)tsa_i->tsa.u.v6addr;

				if (	( !memcmp(addr, &(iph->daddr), 16) || 
					(tsa_i->tsa.dev_idx == in->ifindex) ) &&
					(tsa_i->tsa.port == udph->dest)	) {

					if (ipudp_checksum6_ok(iph, udph))
						priv->tun_recv(skb, p->dev);
					else
						p->dev->stats.tx_dropped++;

					goto done;
				}
			}
		}
	}
	rcu_read_unlock();

	return NF_ACCEPT;
done:
	rcu_read_unlock();
	/* TODO update_fw_table */
	return NF_DROP;
}

__u16 __udp_cheksum(struct iphdr *iph, struct udphdr *udph) {
	__wsum	csum;

	csum = csum_partial(udph, ntohs(udph->len), 0);
	return csum_tcpudp_magic(iph->saddr, iph->daddr, 
				ntohs(udph->len), IPPROTO_UDP, csum);
}

static int
ipudp_checksum4_ok(struct iphdr *iph, struct udphdr *udph) {
	__u16 csum;

	//verify ip csum
	csum = iph->check;
	iph->check = 0;	
	iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);

	if (csum != iph->check)
		return 0;

	//verify udp csum
	csum = udph->check;	
	udph->check = 0;
	udph->check = __udp_cheksum(iph, udph);

	if (csum != udph->check)
		return 0;

	return 1;
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
		if (priv->params.af_out == IPV4) {
			list_for_each_entry_rcu(tsa_i, &(priv->list_tsa), list){
				if (((tsa_i->tsa.u.v4addr == iph->daddr) || 
					(tsa_i->tsa.dev_idx == in->ifindex)) &&
					(tsa_i->tsa.port == udph->dest)) {

					if (iph->frag_off & htons(IP_MF)) {
						//fragmentation not supported	
						p->dev->stats.tx_dropped++;
						goto done;
					}

					if (ipudp_checksum4_ok(iph, udph))
						priv->tun_recv(skb, p->dev);
					else
						p->dev->stats.tx_dropped++;

					goto done;
				}
			}
		}
	}
	rcu_read_unlock();

	return NF_ACCEPT;
done:
	rcu_read_unlock();
	/* TODO update_fw_table */
	return NF_DROP;
}

static int
ipudp_tunnel_xmit(struct sk_buff *skb, struct net_device *dev) {
	struct ipudp_dev_priv * p;	
	ipudp_tun_params *tun = NULL;

	
	p = netdev_priv(dev);

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
	dev->type               = ARPHRD_TUNNEL; //XXX XXX XXX
	dev->flags              = IFF_NOARP/*|IFF_POINTOPOINT*/;
	dev->iflink             = 0;
	dev->addr_len           = 4;
	dev->features           |= NETIF_F_NETNS_LOCAL;
}

static int
__set_viface_mtu(struct net_device *dev){
	int tun_hdr_len;
	ipudp_dev_priv *p = netdev_priv(dev);

	switch(p->params.af_out) {
		case IPV4:
			tun_hdr_len = sizeof(struct iphdr) + sizeof(struct udphdr);	
			break;
		case IPV6:
			tun_hdr_len = sizeof(struct ipv6hdr) + sizeof(struct udphdr);	
			break;
		default:
			return IPUDP_BAD_PARAMS;
	}

	dev->hard_header_len = LL_MAX_HEADER + tun_hdr_len;	
	dev->mtu = ETH_DATA_LEN - tun_hdr_len;

	return 0;
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
	ipudp_list_tun_flush(p);
	ipudp_list_tsa_flush(p);
		
	if (p->params.mode == MODE_MULTI_V4) {
		ipudp_list_rules_flush(p);
		kfree(p->fw_rules);
	}

	return;
}

ipudp_tun_params * 
ipudp_multi_4v_lookup(struct sk_buff *skb, void *q) {
	ipudp_rule_multi_v4 *p;
	struct iphdr *iph = (struct iphdr *)skb->data;
	ipudp_dev_priv *priv = (ipudp_dev_priv *)q; 
	struct list_head *lhead = (struct list_head *)(priv->fw_rules);
	if(skb->protocol != htons(ETH_P_IP))
		return NULL;
	
	if (list_empty(lhead))
		return NULL;

	list_for_each_entry(p, lhead, list) {
		if (!p->tun) return NULL;

		if (p->dest == iph->daddr) 
				return p->tun;
	}
	
	return NULL;
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

void
ipudp_tun4_xmit(struct sk_buff *skb, ipudp_tun_params *tun, struct net_device *dev) {
	void *iph_in = skb->data;
	u16 in_len;
	struct iphdr *iph;
	struct udphdr *udph;
	struct sk_buff *new_skb; 
	struct rtable *rt;
	struct netdev_queue *txq = netdev_get_tx_queue(dev, 0);
	struct net_device_stats *stats = &dev->stats;
	int err;
	

	if (skb->protocol == htons(ETH_P_IP)) 
		in_len = ntohs( ((struct iphdr *)iph_in)->tot_len );
	else if(skb->protocol == htons(ETH_P_IPV6))
		in_len = ntohs( ((struct ipv6hdr *)iph_in)->payload_len ) + sizeof(struct ipv6hdr) ;
	else {
		stats->tx_dropped++;
		goto tx_error;
	}

	if (in_len > dev->mtu) {
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
					.tos 	= 0,
				}
			},
			.proto	= IPPROTO_UDP 
			//.proto 	= IPPROTO_IP
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
		iph_in = skb->data;
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
 		iph				= (struct iphdr *)skb->data;
		iph->version	= 4;
		iph->ihl		= sizeof(struct iphdr)>>2;
		iph->frag_off 	= htons(IP_DF); //XXX
		iph->protocol	= IPPROTO_UDP;
		iph->tos		= 0;
		iph->saddr		= rt->rt_src;
		iph->daddr 		= rt->rt_dst;
		iph->tot_len 	= htons(in_len + IPUDP4_HDR_LEN);
		iph->ttl		= 0x40;
		iph->check 		= 0;
		
		udph 			= (struct udphdr *)(skb->data + 20);
		udph->source	= tun->srcport;
		udph->dest		= tun->destport;
		udph->len 		= htons(in_len + 8);
		udph->check		= 0;

		ip_select_ident(ip_hdr(skb), &rt->u.dst, NULL);
		skb->ip_summed = CHECKSUM_NONE; //it will be computed by ip layer
		udph->check = __udp_cheksum(iph, udph);
	}

	nf_reset(skb);
	skb->mark = tun->mark;

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
ipudp_tun6_xmit(struct sk_buff *skb, ipudp_tun_params *tun, struct net_device *dev) {
	// look at ip6_xmit()
	void *iph_in = skb->data;
	u16 in_len;
	struct ipv6hdr *iph;
	struct udphdr *udph;
	struct sk_buff *new_skb; 
	struct netdev_queue *txq = netdev_get_tx_queue(dev, 0);
	struct net_device_stats *stats = &dev->stats;
	int err;
	struct dst_entry *dst;
	struct rt6_info *rt;
	struct flowi fl;

	if (skb->protocol == htons(ETH_P_IP)) 
		in_len = ntohs( ((struct iphdr *)iph_in)->tot_len );
	else if(skb->protocol == htons(ETH_P_IPV6))
		in_len = ntohs( ((struct ipv6hdr *)iph_in)->payload_len ) + sizeof(struct ipv6hdr) ;
	else {
		stats->tx_dropped++;
		goto tx_error;
	}

	if (in_len > dev->mtu) {
		stats->tx_dropped++;
		goto tx_error;
	}

	{	
		__u8 addr6_any[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
		memset(&fl, 0, sizeof(fl));
		if (!(memcmp(tun->u.v6p.src, &addr6_any, 16)))  {
			if (!(rt = rt6_lookup(dev_net(dev), (struct in6_addr *)tun->u.v6p.dest,  (struct in6_addr *)tun->u.v6p.src, tun->dev_idx, 0))) {
				stats->tx_carrier_errors++;
				goto tx_error;
			}
			memcpy(&fl.fl6_src,&rt->rt6i_idev->addr_list->addr, 16);
			//XXX guess I can get this address also from dst->dev 
			//without another route lookup
		}
		else
			memcpy(&fl.fl6_src, tun->u.v6p.src, 16);

		memcpy(&fl.fl6_dst, tun->u.v6p.dest, 16);
		fl.oif = tun->dev_idx;
		fl.proto = IPPROTO_UDP;	
		dst = ip6_route_output(dev_net(dev), NULL, &fl);
	}

	if (dst->dev == dev) {
		stats->collisions++;
		dst_release(dst);//ip_rt_put(rt); //XXX
		goto tx_error;
	}
	if (skb_headroom(skb) < LL_RESERVED_SPACE(dst->dev) + IPUDP6_HDR_LEN 
			|| skb_shared(skb) || (skb_cloned(skb) && !skb_clone_writable(skb, 0))) {
		new_skb = skb_realloc_headroom(skb, IPUDP6_HDR_LEN);
		if (!new_skb) {
			stats->tx_dropped++;
			dst_release(dst); //ip_rt_put(rt);
			goto tx_error;
		}

		if (skb->sk) 
			skb_set_owner_w(new_skb, skb->sk);

		dev_kfree_skb(skb);
		skb = new_skb;
		iph_in = skb->data;
	}

	skb_push(skb, IPUDP6_HDR_LEN);
	skb_reset_network_header(skb);

	memset(&(IPCB(skb)->opt), 0, sizeof(IPCB(skb)->opt));
	//XXX check
	IPCB(skb)->flags &= ~(IPSKB_XFRM_TUNNEL_SIZE | IPSKB_XFRM_TRANSFORMED | IPSKB_REROUTED);
	skb_dst_drop(skb);
	skb_dst_set(skb, dst);

	//push ipudp tunnel header
	{
 		iph = (struct ipv6hdr *)skb->data;
		*(__be32 *)iph = htonl(0x60000000);
		iph->payload_len = htons(in_len + 8); //no ipv6 options
		iph->nexthdr = IPPROTO_UDP;
		iph->hop_limit = 0x40;
		memcpy(&(iph->saddr), &fl.fl6_src, 16);
		memcpy(&(iph->daddr), &fl.fl6_dst, 16);
		
		udph 			= (struct udphdr *)(skb->data + 40);
		udph->source		= tun->srcport;
		udph->dest		= tun->destport;
		udph->len 		= htons(in_len + 8);
		udph->check		= 0;

		//skb->ip_summed = CHECKSUM_NONE; //it will be computed by ip layer
		udph->check = __udp6_cheksum(iph, udph);
	}

	nf_reset(skb);
	skb->mark = tun->mark;

	//send it
	//there's something wrong... I noticed that this function fails if the
	//arp chache doesn't contain a binding for the destination address.
	//where is the error? here? shouldn't I use rt6_lookup()?
	//XXX to understand XXX
	err = ip6_local_out(skb);

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

static void
__ipudp_tun_recv(struct sk_buff *skb, struct net_device *dev, int pull_len) {
	struct iphdr *ip;
	struct sk_buff *new_skb; 

	new_skb = skb_clone(skb, GFP_ATOMIC);
	secpath_reset(new_skb);
	//new_skb->mac_header = new_skb->network_header;
	skb_pull(new_skb, pull_len);
	//skb_reset_network_header(new_skb);

	ip = (struct iphdr *)new_skb->data;
	if (ip->version == 4)
		new_skb->protocol = htons(ETH_P_IP);

	else if (ip->version == 6)
		new_skb->protocol = htons(ETH_P_IPV6);

	else {
		dev_kfree_skb(new_skb);
		dev->stats.rx_dropped++;
		return;
	}	


	// XXX TODO check if so...
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
ipudp_tun4_recv(struct sk_buff *skb, struct net_device *dev) {	
	__ipudp_tun_recv(skb, dev, IPUDP4_HDR_LEN);
}
void
ipudp_tun6_recv(struct sk_buff *skb, struct net_device *dev) {
	__ipudp_tun_recv(skb, dev, IPUDP6_HDR_LEN);
	return;
}

static int
__ipudp_init_priv_data(ipudp_dev_priv *p) {
	int ret;

	switch(p->params.mode) {
		case MODE_FIXED:
			p->fw_rules = NULL;
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

			//fixed mode: 1 tunnel (1 TSA)
			p->max_tun = 1;
			p->max_tsa = 1;
			break;
		case MODE_MULTI_V4: {
			//this mode has a list of rules linearly inspected
			struct list_head *rules;

			if (p->params.af_out == IPV4) {
				p->tun_xmit = ipudp_tun4_xmit;
				p->tun_recv = ipudp_tun4_recv;
			}
			else {
				ret = IPUDP_BAD_PARAMS;
				goto done;
			}

			rules = kmalloc(sizeof(struct list_head), GFP_ATOMIC);
			INIT_LIST_HEAD(rules);
			p->fw_rules = rules;

			p->fw_lookup = ipudp_multi_4v_lookup;
			p->fw_update = NULL;  //XXX to think about this...

			p->max_tun = 256;
			p->max_tsa = 256;
			p->max_rule = IPUDP_CONF_MAX_RULE_MULTI_V4;
		
			break;
		}
		default:
			ret = IPUDP_BAD_PARAMS;
			goto done;
	}
	
	
	INIT_LIST_HEAD(&(p->list_tun));
	INIT_LIST_HEAD(&(p->list_tsa));

	return IPUDP_OK;

done:
	return ret;
}

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

static int 
__tsa_set_and_reserve_port(ipudp_tun_params *p, ipudp_tsa_params *tsa){
	struct socket *sock;
	int err = IPUDP_OK;
	struct net_device * dev = NULL;
	int addr_len;
	void *addr_ptr = NULL;
	struct inode *inode ;	
	
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
	
			memset(&addr, 0, sizeof(struct sockaddr));
			addr.sin_family = AF_INET;
			addr.sin_addr.s_addr = p->u.v4p.src; //XXX if 0 --> add_any
			addr.sin_port = p->srcport;
		
			if (sock_create_kern(addr.sin_family, SOCK_DGRAM, 
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
		
			memset(&addr, 0, sizeof(struct sockaddr_in6));
			addr.sin6_family = AF_INET6;

			memcpy(&addr.sin6_addr, p->u.v6p.src, 
					sizeof(struct in6_addr)); //XXX if all 0 --> addr_any
			addr.sin6_port = p->srcport;
		
			if (sock_create_kern(addr.sin6_family, SOCK_DGRAM, 
						IPPROTO_UDP, &sock) < 0) {
				err = IPUDP_ERR_TSA_SOCK_CREATE;
				goto err_return;
			}

			memcpy(tsa->u.v6addr, &addr.sin6_addr, 
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

	tsa->sock = sock;
	tsa->af = p->af;
	tsa->port = p->srcport; 

	inode = SOCK_INODE(sock);
	tsa->ino = inode->i_ino;

	return IPUDP_OK;

err_free_sock:	
	kfree(sock);
err_return:
	return err;	
}

 
ipudp_list_tsa_item *
__tsa_already_in_list(ipudp_dev_priv *p, ipudp_tun_params *tun) {
	ipudp_list_tsa_item *t;
	
	list_for_each_entry(t, &(p->list_tsa), list) {
		if (t->tsa.af == IPV4) {
			if (  (t->tsa.u.v4addr == tun->u.v4p.src) &&
						(t->tsa.dev_idx == tun->dev_idx) &&
								(t->tsa.port == tun->srcport) )	

				return t;
		}
		else {
			if (  !memcmp(t->tsa.u.v6addr,tun->u.v6p.src,16) &&
							(t->tsa.dev_idx == tun->dev_idx) &&
									(t->tsa.port == tun->srcport) )	
				return t;
		}
	}
	return NULL;
}

static int 
__ipudp_create_and_add_tsa(ipudp_dev_priv *p, ipudp_tun_params *tun) {
	int ret;
	ipudp_tsa_params tsa;
	ipudp_list_tsa_item *t;

	memset(&tsa,0,sizeof(tsa));

	if (p->tsa_count == p->max_tsa)	
		return IPUDP_ERR_TSA_MAX;

	//check if tsa already in the list
	t = __tsa_already_in_list(p, tun);

	if (t) {
		t->tsa.ref_cnt++;
		goto done;
	}

	if ((ret = __tsa_set_and_reserve_port(tun, &tsa)))
		return ret;
	
	tsa.ref_cnt = 1;

	t = (ipudp_list_tsa_item *)kmalloc(sizeof(*t), GFP_ATOMIC);
	memcpy(&(t->tsa), &tsa, sizeof(tsa));


	list_add_rcu(&(t->list), &(p->list_tsa));

	p->tsa_count ++;

done:
	return IPUDP_OK;
}

static int 
__tun_equal(ipudp_tun_params *p, ipudp_tun_params *q) {
	if (
			//same ports	
			(p->srcport == q->srcport) &&
			(p->destport == q->destport) &&
			//same real dev
			(p->dev_idx == q->dev_idx) &&
			//same af
			(p->af == q->af) &&
			//same addresses
			(!(memcmp(&(p->u),&(q->u),32)))
	   )
		return 1;
	else 
		return 0;
}

static int
__tun_already_in_list(struct list_head *lhead, ipudp_tun_params *tun) {
	ipudp_list_tun_item *t;

	if (list_empty(lhead))
		return 0;

	list_for_each_entry(t, lhead, list) {	
		if(__tun_equal(&(t->tun), tun)) {
			return IPUDP_ERR_TUN_EXISTS;	
		}
	}

	return 0;
}


//TODO make a sub function for the following 2 insert()
static int 
__list_tun_insert(ipudp_list_tun_item *new, struct list_head *lhead) {
	struct list_head *p = lhead;
	ipudp_list_tun_item *item;

	new->tun.tid = 1;
	
	if (list_empty(lhead))
		goto done;

	list_for_each(p, lhead) {
		item = list_entry(p, ipudp_list_tun_item, list);

		if (item->tun.tid != new->tun.tid) {
			goto done;
		}
		(new->tun.tid)++;
	}

done:
	list_add_rcu(&(new->list), p->prev);
	return IPUDP_OK;
}

static int 
__list_rule_multi_v4_insert(ipudp_rule_multi_v4 * new, struct list_head *lhead) {
	struct list_head *p = lhead;
	ipudp_rule_multi_v4 *entry;

	new->id = 1;

	if (list_empty(lhead))
		goto done;

	list_for_each(p, lhead) {
		entry = list_entry(p, ipudp_rule_multi_v4, list);

		if (entry->id != new->id) {
			goto done;
		}
		(new->id)++;
	}

done:
	list_add_rcu(&(new->list), p->prev);
	return IPUDP_OK;
}

int
ipudp_bind_tunnel(ipudp_viface_params *p, ipudp_tun_params *tun) {
	int ret;
	ipudp_dev *viface;
	ipudp_list_tun_item *item;
	struct ipudp_dev_priv *priv;


	item = (ipudp_list_tun_item *)kmalloc(sizeof(*item), GFP_ATOMIC);
	memcpy(&(item->tun), tun, sizeof(*tun));
	
	spin_lock_bh(&ipudp_lock);

	viface =__list_ipudp_dev_locate_by_name(p->name);

	if (!viface) {
		ret = IPUDP_ERR_DEV_NOT_FOUND;
		goto err_ret;
	}
	priv = (ipudp_dev_priv *)netdev_priv(viface->dev);	

	if (priv->tun_count == priv->max_tun) {	
		ret = IPUDP_ERR_TUN_MAX;
		goto err_ret;
	}

	//check tun parameters
	if ((ret = __tun_already_in_list(&(priv->list_tun), tun)))
		goto err_ret;

	if(  (( __tun_src_is_null(tun)) && (!(tun->dev_idx)))
		|| __tun_dst_is_null(tun) || (!(tun->destport)) 
						|| (!(tun->srcport)) )
	{
		ret = IPUDP_ERR_TUN_BAD_PARAMS;
		goto err_ret;
	}

	if (priv->params.af_out != tun->af) {
		ret = IPUDP_ERR_TUN_BAD_PARAMS;
		goto err_ret;
	}

	/* reserve listening port and add tsa to list */
	if ((ret = __ipudp_create_and_add_tsa(priv, tun))) 
		goto err_ret;

	/* add tunnel to list */
	//list_add_rcu(&(item->list), &(priv->list_tun));
	if ((ret = __list_tun_insert((ipudp_list_tun_item *)&(item->list), &(priv->list_tun))))
		goto err_ret;

	priv->tun_count++;

	spin_unlock_bh(&ipudp_lock);

	return IPUDP_OK;
	
err_ret:
	spin_unlock_bh(&ipudp_lock);
	return ret;
}


//XXX make it more general and call a callback to actually add the rule TODO
//instead of having a switch() here.
int
ipudp_add_rule(ipudp_viface_params *p, void *rule) {
	int ret;
	ipudp_dev *dev;
	ipudp_dev_priv	*priv;
	ipudp_list_tun_item	*tun_i;

	spin_lock_bh(&ipudp_lock);

	dev = __list_ipudp_dev_locate_by_name(p->name);

	if (!dev) {
		ret = IPUDP_ERR_DEV_NOT_FOUND;
		goto done;
	}

	priv = netdev_priv(dev->dev);
			
	if (priv->fw_rules == NULL) {	
		ret = IPUDP_ERR_RULE_NOT_SUPPORTED;
		goto done;
	}

	if (priv->rule_count == priv->max_rule) {
		ret = IPUDP_ERR_RULE_MAX;
		goto done;
	}

	switch(priv->params.mode) {
		case MODE_MULTI_V4: {
			ipudp_rule_multi_v4 *new;
			ipudp_rule_multi_v4 *r = (ipudp_rule_multi_v4 *)rule;
			
			list_for_each_entry(tun_i, &priv->list_tun, list) {
				if (tun_i->tun.tid == r->tun_id) {

					new = kzalloc(sizeof(ipudp_rule_multi_v4), GFP_ATOMIC);
					new->dest = r->dest;
					new->type = r->type;
					new->tun = &(tun_i->tun);
					new->tun_id = r->tun_id;
					__list_rule_multi_v4_insert(new, (struct list_head *)priv->fw_rules);
					priv->rule_count++;

					ret = IPUDP_OK;
					goto done;
				}
			}
	
			ret = IPUDP_ERR_TUN_NOT_FOUND;
			goto done;
		}

		default:
			ret = IPUDP_ERR_RULE_NOT_SUPPORTED;
			goto done;
	}

done:
	spin_unlock_bh(&ipudp_lock);
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

	//set device MTU and HRD_LEN by mode
	if ((err = __set_viface_mtu(dev)))
		goto err_init_priv;	

	//register net device
	if (register_netdev(dev)) {
		err = IPUDP_ERR_DEV_REG;
		goto err_reg_dev;
	}

	//add dev to internal list 
	__list_dev_add(dev); 
	
	return IPUDP_OK;

err_reg_dev:
	free_netdev(dev);
err_init_priv:
	ipudp_clean_priv(ipudp_priv);
err_alloc_name:
err_dev_alloc:
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
	nf_unregister_hook(ipudp->nf_hook_ops_6_in);
	ipudp_genl_unregister();
	kfree(ipudp->nf_hook_ops_in);
	kfree(ipudp);
	printk(KERN_INFO "UMPT module unloaded\n");
}

module_init(ipudp_init);
module_exit(ipudp_fini);
MODULE_LICENSE("GPL");
