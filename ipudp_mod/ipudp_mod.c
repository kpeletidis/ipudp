#ifndef __KERNEL__
#define __KERNEL__
#endif

#ifndef MODULE
#define MODULE
#endif
/*XXX*/

#include "ipudp.h"

LIST_HEAD(ipudp_viface_list);

static ipudp_data *ipudp;
static int __ipudp_init_priv_data(ipudp_dev_priv *);
static void  __ipudp_free_priv(ipudp_dev_priv *);
static ipudp_dev * __list_ipudp_dev_locate_by_name(char *); 

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
		p = __list_ipudp_dev_locate_by_name(name);

		if (p)
				return netdev_priv(p->dev);
		else 
				return NULL;
}

static void 
__list_ipudp_dev_init(void) {
		ipudp->viface_list = &ipudp_viface_list;
		ipudp->viface_count = 0;
}

static void 
__list_ipudp_dev_fini(void) {
		ipudp_dev *p,*q;
		ipudp_dev_priv *priv;
	
		list_for_each_entry_safe(p, q, ipudp->viface_list, list) {
				priv = netdev_priv(p->dev);
				__ipudp_free_priv(priv);	
				list_del(&(p->list));
				unregister_netdev(p->dev);
				kfree(p);
		}
		ipudp->viface_count = 0;
}

static ipudp_dev * 
__list_ipudp_dev_locate_by_name(char *name) {
		ipudp_dev * p;

		list_for_each_entry(p, ipudp->viface_list, list) {
				if (!strcmp(name, p->dev->name))
						return p;
		}
		return NULL;
}

static void 
__list_ipudp_dev_add(struct net_device * dev){
		ipudp_dev * p;

		p = kzalloc(sizeof(ipudp_dev), GFP_KERNEL);
		p->dev = dev;

		list_add(&(p->list), ipudp->viface_list);
		ipudp->viface_count ++;	
}

static void 
__list_ipudp_dev_del(ipudp_dev * p){	
		ipudp_dev_priv *priv = netdev_priv(p->dev);
		__ipudp_free_priv(priv);
		list_del(&(p->list));
		ipudp->viface_count --;	
}

void 
ipudp_list_tun_add(ipudp_dev_priv *p, ipudp_tun_params *tun){ 
		ipudp_list_tun_item *item;

		item = (ipudp_list_tun_item *)kmalloc(sizeof(*item), GFP_KERNEL);
		memcpy(&(item->tun), tun, sizeof(*tun));
	
		/*XXX respesct tid order XXX*/
		//if(list_empty(priv->list_tun.next))	
		//	list_add(&(item->list), &(p->list_tun));
	
		//list_for_each_entry(p, &(priv->list_tun.next), list) {	
		//}

		list_add(&(item->list), &(p->list_tun));
		p->tun_count++;
}

void 
ipudp_list_tun_del(ipudp_dev_priv *p, ipudp_tun_params *tun) {
		//TODO	
		return;
}

void
ipudp_list_tun_fini(ipudp_dev_priv *priv) {
		ipudp_list_tun_item *p,*q;
	
		list_for_each_entry_safe(p, q, &(priv->list_tun), list) {
				list_del(&(p->list));
				kfree(p);
		}
		priv->tun_count = 0;
}
void 
ipudp_list_tsa_add(ipudp_dev_priv *p, ipudp_tsa_params *tsa) {
		ipudp_list_tsa_item *item;
	
		item = (ipudp_list_tsa_item *)kmalloc(sizeof(*item), GFP_KERNEL);
		memcpy(&(item->tsa), tsa, sizeof(*tsa));
		list_add(&(item->list), &(p->list_tsa));
		p->tsa_count ++;
}

void 
ipudp_list_tsa_del(ipudp_dev_priv *p, ipudp_tsa_params *tsa) {
		//TODO	
		return;
}

void 
ipudp_list_tsa_fini(ipudp_dev_priv *priv) {
		ipudp_list_tsa_item *p,*q;
	
		list_for_each_entry_safe(p, q, &(priv->list_tsa), list) {
				list_del(&(p->list));
				sock_release(p->tsa.sock);
                kfree(p);
		}
		priv->tsa_count = 0;
		return;
}

static void 
ipudp_tunnel_uninit(struct net_device *dev) {
		/*TODO*/
		printk(KERN_INFO "TODO ipudp_tunnel_uninit\n");
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
	
#if 0	
		printk("saddr %d.%d.%d.%d daddr %d.%d.%d.%d dport %d sport %d\n",
				NIPQUAD(iph->saddr),NIPQUAD(iph->daddr),
				ntohs(udph->dest),ntohs(udph->source));
#endif	

		//TODO LOCK - this is a softirq that shares data with:
		//(1)other pck recv handler (2) packet xmit
		//(3)netlink msg handler (4) ioctl
		// check if there is a TSA registered for this packet
		list_for_each_entry(p, ipudp->viface_list, list) {
				priv = netdev_priv(p->dev);
				list_for_each_entry(tsa_i, &(priv->list_tsa), list) {
						if ((tsa_i->tsa.u.v4addr == iph->daddr) && 
										(tsa_i->tsa.port == udph->dest)) {

								priv->tun_recv(skb, priv);
								return NF_DROP;
						}
				}
		}

		return NF_ACCEPT;
}

static int
ipudp_tunnel_xmit(struct sk_buff *skb, struct net_device *dev) {
		struct ipudp_dev_priv * p;	
		ipudp_tun_params *tun = NULL;

		p = netdev_priv(dev);

		if (!(tun = p->fw_lookup(skb, p)))
				goto err;
		
		p->tun_xmit(skb, tun);	
	
		//TODO dev STATISTICS;	
err:
		kfree(skb);
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
		//dev->features           |= 0/*TODO*/;
}

static int 
ipudp_nf_init(struct nf_hook_ops *p) {
		int err;

		p->hook 	= ipudp_tsa4_rcv;
		p->pf		= PF_INET;
		p->hooknum	= NF_INET_PRE_ROUTING;
		p->priority	= NF_IP_PRI_FIRST;
        
		if ((err = nf_register_hook(p)))
				kfree(p);

		//TODO register IPV4 hook
		return err;
}

static int __inline 
new_dev_not_allowed(void) {
		if ((ipudp->viface_count) < (ipudp->conf.max_dev_num))
				return 0;
		return -1;
}

int  
ipudp_del_viface(ipudp_viface_params *p) {	
		static ipudp_dev * viface; 
		ipudp_dev_priv *priv;	
				
		viface = __list_ipudp_dev_locate_by_name(p->name);
			
		if (!viface)
				return IPUDP_ERR_DEV_NOT_FOUND;

		priv = netdev_priv(viface->dev);
			
		memcpy(p, &(priv->params), sizeof(*p));
			
		__list_ipudp_dev_del(viface);
		unregister_netdev(viface->dev);		
			
		__ipudp_free_priv(priv);

		kfree(viface);

		return IPUDP_OK;
}

static void 
__ipudp_free_priv(ipudp_dev_priv * p) {
		/* free tun list */
		ipudp_list_tun_fini(p);
		/* free tsa list */
		ipudp_list_tsa_fini(p);

		/* TODO */
		return;
}


ipudp_tun_params * 
ipudp_fixed_out_tun(struct sk_buff *buff, void *priv) {
		ipudp_list_tun_item *item;
		item = (ipudp_list_tun_item *)(((ipudp_dev_priv *)priv)->list_tun.next);
		return (ipudp_tun_params *)&(item->tun);
}

int 
ipudp_tun4_xmit(struct sk_buff *buf, ipudp_tun_params *tun) {
		//TODO
		printk("ipudp: tun4 xmit\n");
		return 0;
}

int 
ipudp_tun6_xmit(struct sk_buff *buf, ipudp_tun_params *tun) {
		//TODO
		return 0;
}

int 
ipudp_tun4_recv(struct sk_buff *buf, void *priv) {
		//TODO
		printk("ipudp: tun4 recv\n");
		return 0;
}

int 
ipudp_tun6_recv(struct sk_buff *buf, void *priv) {
		//TODO
		return 0;
}

static int
__ipudp_init_priv_data(ipudp_dev_priv *p) {
		int ret;

		switch(p->params.mode) {
				case MODE_FIXED:
						p->fw_table = NULL;
						p->fw_lookup = ipudp_fixed_out_tun;
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

/*XXX LOCK XXX*/
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
		else //cant happen 
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

		memset(&tsa,0,sizeof(tsa));

		if (p->tsa_count == p->max_tsa)	
				return IPUDP_ERR_TSA_MAX;

		if ((ret = __tsa_reserve_port(tun, &tsa)))
				return ret;

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

		viface =__list_ipudp_dev_locate_by_name(p->name);
		if (!viface) {
				ret = IPUDP_ERR_DEV_NOT_FOUND;
				goto err_ret;
		}
		priv = (ipudp_dev_priv *)netdev_priv(viface->dev);

#if 0
		printk("ipudp_bind_tunnel:p->name %s tun->type %d mode %d",
					p->name, tun->af, priv->params.mode);

		if (tun->af == IPV4) {
				printk("daddr: %d.%d.%d.%d", NIPQUAD(tun->u.v4p.dest));
				printk("daddr: %d.%d.%d.%d", NIPQUAD(tun->u.v4p.src));
		}
		printk("sport: %d ", (int)ntohs(tun->srcport));
		printk("dport: %d ", (int)ntohs(tun->destport));
		printk("iface idx %d\n", (int)tun->dev_idx);
#endif

		if (priv->tun_count == priv->max_tun) {	
				ret = IPUDP_ERR_TUN_MAX;
				goto err_ret;
		}

		if (priv->params.mode != MODE_FIXED) {
				//tun->tid = __get_new_tid(&(priv->list_tun));TODO
				ret = IPUDP_ERR_TUN_BAD_PARAMS; //TODO
				goto err_ret;
		}
	
		if(  (( __tun_src_is_null(tun)) && (!(tun->dev_idx)) )
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
		else	{
				//printk("Adding %s\n", p->name);
				dev = alloc_netdev(sizeof(*ipudp_priv),p->name,
										ipudp_tunnel_setup);
				//err = IPUDP_ERR_DEV_NAME;
				//goto err_dev_alloc;
		}

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
	
		/* TODO write the function */
		err = __ipudp_init_priv_data(ipudp_priv);
		if (err)
				goto err_init_priv;	

		//register net device
		if (register_netdev(dev)) {
				err = IPUDP_ERR_DEV_REG;
				goto err_reg_dev;
		}

		__list_ipudp_dev_add(dev); 

		return IPUDP_OK;

err_reg_dev:
		free_netdev(dev);
err_init_priv:
		__ipudp_free_priv(ipudp_priv);
err_alloc_name:
err_dev_alloc:
		return err;

}

static int __init ipudp_init(void) {
		int err = 0;
		struct nf_hook_ops *p;

		printk(banner);

		ipudp = kzalloc(sizeof(ipudp_data), GFP_KERNEL);
		
		__conf_init();
		__list_ipudp_dev_init();
	
		if ((err = ipudp_genl_register())) 
				goto err_genl_register;

		p = kzalloc(sizeof(struct nf_hook_ops), GFP_KERNEL);

		if ((err = ipudp_nf_init(p)))
				goto err_nf_hook;

		ipudp->nf_hook_ops_in = p;

		return 0;

err_nf_hook:
		kfree(p);
err_genl_register:
//err_ipudp_dev_alloc:
		kfree(ipudp);
		return err;
}

static void __exit ipudp_fini(void) {

		__list_ipudp_dev_fini();
		nf_unregister_hook(ipudp->nf_hook_ops_in);
		ipudp_genl_unregister();
		kfree(ipudp->nf_hook_ops_in);
		kfree(ipudp);
		printk(KERN_INFO "UMPT module unloaded\n");
}

module_init(ipudp_init);
module_exit(ipudp_fini);
MODULE_LICENSE("GPL");
