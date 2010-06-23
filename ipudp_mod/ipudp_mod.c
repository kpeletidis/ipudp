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


static const char banner[] __initconst =
	KERN_INFO "Tunneling - IP over IP/UDP - module\n";

static void __conf_init(void) {
	ipudp->conf.max_dev_num = IPUDP_CONF_MAX_DEV;
	ipudp->conf.default_mode = MODE_FIXED; 
	ipudp->conf.default_af_out = IPV4;
}


struct list_head * ipudp_get_viface_list(void) {
	
	return ipudp->viface_list;
}

int ipudp_get_viface_count(void) {

	return ipudp->viface_count;
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

typedef struct
_ipudp_list_tun_item{
	struct list_head list;
	ipudp_tun_params tun;
}ipudp_list_tun_item;

void 
ipudp_list_tun_add(ipudp_dev_priv *p, ipudp_tun_params *tun) {
	ipudp_list_tun_item *item, *q;
	
	item = (ipudp_list_tun_item *)kmalloc(sizeof(*item), GFP_KERNEL);
	memcpy(&(item->tun), tun, sizeof(*tun));
	
	/*XXX respesct tid order XXX*/
	//if(list_empty(priv->list_tun.next))	
		list_add(&(item->list), &(p->list_tun));
	
	//list_for_each_entry(p, &(priv->list_tun.next), list) {	
	//}

	list_add(&(item->list), &(p->list_tun));
	//list_add_tail(&(item->list), &(p->list_tun));
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

typedef struct
_ipudp_list_tsa_item{
	struct list_head list;
	ipudp_tsa_params tsa;
}ipudp_list_tsa_item;

void 
ipudp_list_tsa_add(ipudp_dev_priv *p, ipudp_tsa_params *tsa) {
	ipudp_list_tsa_item *item;
	
	item = (ipudp_list_tsa_item *)kmalloc(sizeof(*item), GFP_KERNEL);
	memcpy(&(item->tsa), tsa, sizeof(*tsa));
	list_add(&(item->list), &(p->list_tsa));
	p->tsa_count ++;
	return;
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
ipudp_tunnel_rcv(unsigned int hooknum,  
                  struct sk_buff *skb,
                  const struct net_device *in,
                  const struct net_device *out,
                  int (*okfn)(struct sk_buff*)) {
	

	//return NF_DROP;
	return NF_ACCEPT;
}

static int
ipudp_tunnel_xmit(struct sk_buff *skb, struct net_device *dev) {
	struct ipudp_dev_priv * p;	

	p = netdev_priv(dev);

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

        p->hook 	= ipudp_tunnel_rcv;
        p->pf		= PF_INET;
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

int  
ipudp_del_viface(ipudp_viface_params *p) {	
	static ipudp_dev * viface; 
	ipudp_dev_priv *priv;	
		
	viface = __list_ipudp_dev_locate_by_name(p->name);
	priv = netdev_priv(viface->dev);
	
	if (!viface)
		return IPUDP_ERR_DEV_NOT_FOUND;

	memcpy(p, &(priv->params), sizeof(*p));
	
	__list_ipudp_dev_del(viface);
	unregister_netdev(viface->dev);		
	
	__ipudp_free_priv(priv);

	kfree(viface);

	return IPUDP_OK;
}

static void 
__ipudp_free_priv(ipudp_dev_priv * p) {
	/*TODO*/
	/* free tun list */
	/* free tsa list */
	/* free fw_table */
	return;
}

static int
__ipudp_init_priv_data(ipudp_dev_priv *p) {
	//init tun list
	p->list_tun.prev = &p->list_tun;
	p->list_tun.next = &p->list_tun;
	//init tsa list
	p->list_tsa.prev = &p->list_tsa;
	p->list_tsa.next = &p->list_tsa;

	p->max_tun = IPUDP_CONF_MAX_TUN;
	p->max_tsa = IPUDP_CONF_MAX_TSA;
	
	return IPUDP_OK;
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
__tun_addr_is_null(int vers, __u8 *addr) {
	int i;

	switch(vers) {
		case IPV4:
			if ( ((__u32)(*addr))  == 0)
				return 1;
			break;
		case IPV6:
			for (i = 0; i < IPV6_ADDR_LEN; i++) {
				if (addr[i]) return 1;
			}
		break;
	}
	return 0;
}

static int 
__tun_src_is_null(ipudp_tun_params *p) {
	int vers = p->af;
	void *addr;

	switch(vers) {
		case IPV4:
			addr = &(p->u.v4p.src);
			break;
		case IPV6:
			addr = p->u.v6p.src;
			break;
		default:
			return -1;
			
	}		
	return __tun_addr_is_null(vers, addr);  
}

static int 
__tun_dst_is_null(ipudp_tun_params *p) {
	int vers = p->af;

	return 0;
}

/*
int __tun_reserve_port(ipudp_tun_parameters *p){
	struct sockaddr_in addr;
	__u16 port = p->srcport
	int sock;

	if(sock_create(AF_INET, SOCK_DGRAM, IPPROTO_UDP, &sock) < 0)
		//
		return -2;

	memset(&addr, 0, sizeof(struct sockaddr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(port);

	if(tmp->sock->ops->bind(tmp->sock, (struct sockaddr *)&addr, sizeof(struct sockaddr)) < 0){
		printk("reserve_port - Error - Unable to bind port %u", port);
		kfree(tmp);
		return -1; //TODO check the errno variable to understand the origin of the error
	}

	list_add(&tmp->list, &spl->list);
	return 0;
}
*/
int
ipudp_bind_tunnel(ipudp_viface_params *p, ipudp_tun_params *tun) {
	int ret;
	ipudp_dev *viface;
	struct ipudp_dev_priv *priv;
	int sock;
	ipudp_tun_params *t;
	ipudp_tsa_params *tsa;

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
	if (p->mode != MODE_FIXED)
		;//tun->tid = __get_new_tid(&(priv->list_tun));TODO


	if( (!(__tun_src_is_null(tun)) && !(tun->dev_idx)) ||
		__tun_dst_is_null(tun) || (!(tun->destport)) || (!(tun->srcport)) )
	{
		ret = IPUDP_ERR_TUN_BAD_PARAMS;
		goto err_ret;
	}

	/*XXX add tsa and bind port */
	

#if 0	

void release_port(u16 port){
	struct spl_entry *tmp;

	tmp = search_port(port);
	if(tmp != NULL){
		tmp->n--;
		if(tmp->n < 0) printk("\n !-WARNING-! - release_port - n with negative value");
		if(tmp->n <= 0){
			sock_release(tmp->sock);
			list_del(&tmp->list);
			kfree(tmp);
		}
	}
}

			tun_size = sizeof(ipudp_tun4_params);
			
			tsa_size = sizeof(ipudp_tsa4_params);
			//XXX socket bind to port (random or given)
			sock = 0;
			//XXX TODO
			//tsa = NULL; // kmalloc();
			//tsa->sock = sock;
			//__list_tsa_add(priv, t);
		}
			break;
		case IPV6: 
		{
			ipudp_tun6_params *tun6;
			tun6 = (ipudp_tun6_params *)t;

			tun_size = sizeof(ipudp_tun6_params);
		}
			break;
		default:
			ret = IPUDP_BAD_PARAMS;
			goto err_ret;
			break;
	}


	t = kmalloc(tun_size, GFP_KERNEL);
	memcpy(t, tun, tun_size);
	__list_tun_add(priv, t);
#endif

	/*XXX should I check tunnel_params here?
	Is it ok to do it in genl handler?*/
	
	#if 0
	switch(p->af_out){
		case IPV4:
		{
			ipudp_tun4_params *tun4 = (ipudp_tun4_params *)tun;
			ipudp_tun4_params *t4;
			
			t4 = kmalloc(sizeof(*t4), GFP_KERNEL);
			memcpy(t4, tun4, sizeof(*t4));
			
			__list_tun_add(priv, t4);
		}
		break;

		case IPV6: //XXX TODO XXX
		{
			ret = IPUDP_BAD_PARAMS;
			goto err_ret;
			//ipudp_tun6_params *t4 = (ipudp_tun6_params *)tun;
		}
		break;
		default:
			//shouldn't happen
			ret = IPUDP_BAD_PARAMS;
			goto err_ret;
		break; 
	}
	#endif
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
