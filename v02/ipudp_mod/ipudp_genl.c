#include <linux/version.h>
#include "ipudp.h"

#define COMP_LINUX_VERSION_CODE 132640

//XXX TODO XXX set_msg_attr ugly 
//XXX TODO XXX a lot of code can be grouped in subfunctions..

static struct 
nla_policy ipudp_genl_policy[__IPUDP_A_MSG_MAX] = {
	[IPUDP_A_UNSPEC]	= { .type = NLA_STRING },
	[IPUDP_A_STRING]	= { .type = NLA_STRING }, //TODO useless?
	[IPUDP_A_CMD_SPEC]	= { .type = NLA_U32 },
	[IPUDP_A_VIFACE_PARAMS] = { .type = NLA_BINARY },
	[IPUDP_A_TUN_PARAMS] 	= { .type = NLA_BINARY },
	[IPUDP_A_RULE_PARAMS] 	= { .type = NLA_BINARY },
	[IPUDP_A_LIST_PARAMS] 	= { .type = NLA_BINARY },
	[IPUDP_A_RET_CODE] 	= { .type = NLA_U32 },
	[IPUDP_A_ERROR_DESC]	= { .type = NLA_STRING }, //TODO useless?
};

static struct 
genl_family ipudp_gnl_family = {
	.id = GENL_ID_GENERATE,
	.hdrsize = 0,
	.name = IPUDP_GNL_FAMILY_NAME,
	.version = IPUDP_GNL_FAMILY_VERSION,
	.maxattr = IPUDP_A_MSG_MAX,
};

static void *
extract_nl_attr(const struct genl_info *info, const int atype){
	struct nlattr *na;
	void *data = NULL;
	na = info->attrs[atype];
	if (na) 
		data = nla_data(na);
	
	return data;
}

static void 
set_msg_attr(struct ipudp_nl_msg_attr *m, int atype, void *data, int len, int str, int *n){
	*n = *n + 1;
	m->is_string = str; 
	m->atype = atype;
	m->data = data;
	m->len 	= len;
}

static int 
send_nl_msg(const int command, const unsigned int n_data, u8 msg_type, 
	const struct ipudp_nl_msg_attr *msg_data, const struct genl_info *info){
	
	struct sk_buff *skb;
	void *skb_head;
	unsigned int i;
	u16 flags = 0;


	skb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (skb == NULL){
		printk("ipudp_send_nl_msg: unable to allocate skb\n");
		return -1;
	}

	if (msg_type == MSG_REQUEST)
		flags |= NLM_F_REQUEST;

	skb_head = genlmsg_put(skb, 0, info->snd_seq+1, &ipudp_gnl_family, flags, command);
	if (skb_head == NULL) {
		printk("ipudp_send_nl_msg: unable to allocate skb_head\n");
		return -ENOMEM;
	}


	for(i=0; i<n_data; i++){
		if (msg_data[i].is_string) {
			if(nla_put_string(skb, msg_data[i].atype, msg_data[i].data)){
				printk("ipudp_send_nl_msg: error putting attributes\n");
				return -1;
			}
		}
	
		else {
			if(nla_put(skb, msg_data[i].atype, msg_data[i].len, msg_data[i].data)){
				printk("ipudp_send_nl_msg: error putting attributes\n");
				return -1;
			}
		}
	}

	genlmsg_end(skb, skb_head);

#if LINUX_VERSION_CODE < COMP_LINUX_VERSION_CODE
	if(genlmsg_unicast(skb, info->snd_pid ) != 0){
#else
	if(genlmsg_unicast(&init_net, skb, info->snd_pid ) != 0){
#endif
		printk("ipudp_send_nl_msg: error sending message\n");
		return -1;
	}

	return 0;
}

static int 
ipudp_genl_do_add(struct sk_buff *skb, struct genl_info *info){
	struct ipudp_nl_msg_attr attr[3]; //ugly fixed number of attrs...
	int n_attr = 0;
	__u32 ret_code;
	ipudp_nl_cmd_spec *cmd_spec;	

	cmd_spec = (ipudp_nl_cmd_spec *)extract_nl_attr(info, IPUDP_A_CMD_SPEC);

	if (!cmd_spec) {
		ret_code = IPUDP_BAD_MSG_FORMAT;
		//set_msg_attr(&attr[n_attr], IPUDP_A_RET_CODE, 
		//	&ret_code, sizeof(ret_code), 0, &n_attr);
		goto done;	
	}
	
	switch(*cmd_spec){
		case CMD_S_VIFACE:
		{	
			ipudp_viface_params *p =  NULL;
			p = (ipudp_viface_params *)
			extract_nl_attr(info, IPUDP_A_VIFACE_PARAMS);
		
			if (!p)	{	
				ret_code = IPUDP_BAD_PARAMS;	
				//set_msg_attr(&attr[n_attr], IPUDP_A_RET_CODE, 
				//	&ret_code, sizeof(ret_code), 0, &n_attr);
				goto done;
			}

			ret_code = ipudp_add_viface(p);
	
			set_msg_attr(&attr[n_attr], IPUDP_A_VIFACE_PARAMS, p, 
						sizeof(*p), 0, &n_attr);

	
			goto done;
		}
		break;
		case CMD_S_TUN:
		{
			ipudp_viface_params *viface = NULL;
			ipudp_tun_params *tun = NULL;
		
			viface = (ipudp_viface_params *)
				extract_nl_attr(info, IPUDP_A_VIFACE_PARAMS);

			if (!viface) {
				ret_code = IPUDP_BAD_PARAMS;	
				goto done;
			}

			tun = (ipudp_tun_params *)
				extract_nl_attr(info, IPUDP_A_TUN_PARAMS);

			if (!tun) {
				ret_code = IPUDP_BAD_PARAMS;	
				goto done;
			}
			ret_code = ipudp_bind_tunnel(viface, tun);
			break;
		}	
		case CMD_S_RULE:
		{
			ipudp_viface_params *viface = NULL;
			void *rule = NULL;
		
			viface = (ipudp_viface_params *)
				extract_nl_attr(info, IPUDP_A_VIFACE_PARAMS);

			if (!viface) {
				ret_code = IPUDP_BAD_PARAMS;	
				goto done;
			}

			rule = (ipudp_tun_params *)
				extract_nl_attr(info, IPUDP_A_RULE_PARAMS);

			if (!rule) {
				ret_code = IPUDP_BAD_PARAMS;	
				goto done;
			}
			ret_code = ipudp_add_rule(viface, rule);
			break;

			break;	
		}
		break;
		default:
			ret_code = IPUDP_BAD_CMD_SPEC;	
			goto done;
		break;	
	}
	
done:
	set_msg_attr(&attr[n_attr], IPUDP_A_RET_CODE, &ret_code, 
			sizeof(ret_code), 0, &n_attr);

	return send_nl_msg(IPUDP_C_ADD, n_attr, MSG_REPLY, attr, info);

}

static int 
ipudp_genl_do_del(struct sk_buff *skb, struct genl_info *info){
	struct ipudp_nl_msg_attr attr[3];//ugly fixed number of attrs...
	int n_attr = 0;
	__u32 ret_code;
	ipudp_nl_cmd_spec *cmd_spec;	


	cmd_spec = (ipudp_nl_cmd_spec *)extract_nl_attr(info, IPUDP_A_CMD_SPEC);

	if (!cmd_spec) {
		ret_code = IPUDP_BAD_MSG_FORMAT;
		set_msg_attr(&attr[n_attr], IPUDP_A_RET_CODE, 
				&ret_code, sizeof(ret_code), 0, &n_attr);
		goto done;	
	}

	switch(*cmd_spec){
		case CMD_S_VIFACE:
		{	
			ipudp_viface_params *p =  NULL;
			p = (ipudp_viface_params *)extract_nl_attr(info, IPUDP_A_VIFACE_PARAMS);
			if (!p)	{	
				ret_code = IPUDP_BAD_PARAMS;	
				set_msg_attr(&attr[n_attr], IPUDP_A_RET_CODE, &ret_code, 
						sizeof(ret_code), 0, &n_attr);
				goto done;
			}
		

			ret_code = ipudp_del_viface(p);

			set_msg_attr(&attr[n_attr], IPUDP_A_RET_CODE, &ret_code, 
					sizeof(ret_code), 0, &n_attr);
			set_msg_attr(&attr[n_attr], IPUDP_A_VIFACE_PARAMS, p, 
					sizeof(*p), 0, &n_attr);
			break;
		}
		case CMD_S_TUN:
		{
			ipudp_tun_params *p =  NULL;
			ipudp_viface_params *q = NULL;

			p = (ipudp_tun_params *)extract_nl_attr(info, IPUDP_A_TUN_PARAMS);
			if (!p)	{	
				ret_code = IPUDP_BAD_PARAMS;	
				set_msg_attr(&attr[n_attr], IPUDP_A_RET_CODE, &ret_code, 
						sizeof(ret_code), 0, &n_attr);
				goto done;
			}
			
			q = (ipudp_viface_params *)extract_nl_attr(info, IPUDP_A_VIFACE_PARAMS);
			if (!q)	{	
				ret_code = IPUDP_BAD_PARAMS;	
				set_msg_attr(&attr[n_attr], IPUDP_A_RET_CODE, &ret_code, 
						sizeof(ret_code), 0, &n_attr);
				goto done;
			}
			
			ret_code = ipudp_del_tun(q,p);
	
			set_msg_attr(&attr[n_attr], IPUDP_A_RET_CODE, &ret_code, 
					sizeof(ret_code), 0, &n_attr);
			set_msg_attr(&attr[n_attr], IPUDP_A_TUN_PARAMS, p, 
					sizeof(*p), 0, &n_attr);
			break;
		}
		case CMD_S_RULE:
		{
			ipudp_rule *p =  NULL;
			ipudp_viface_params *q = NULL;

			p = (ipudp_rule *)extract_nl_attr(info, IPUDP_A_RULE_PARAMS);
			if (!p)	{	
				ret_code = IPUDP_BAD_PARAMS;	
				set_msg_attr(&attr[n_attr], IPUDP_A_RET_CODE, &ret_code, 
						sizeof(ret_code), 0, &n_attr);
				goto done;
			}
			
			q = (ipudp_viface_params *)extract_nl_attr(info, IPUDP_A_VIFACE_PARAMS);
			if (!q)	{	
				ret_code = IPUDP_BAD_PARAMS;	
				set_msg_attr(&attr[n_attr], IPUDP_A_RET_CODE, &ret_code, 
						sizeof(ret_code), 0, &n_attr);
				goto done;
			}
			
			ret_code = ipudp_del_rule(q,p);
	
			set_msg_attr(&attr[n_attr], IPUDP_A_RET_CODE, &ret_code, 
					sizeof(ret_code), 0, &n_attr);
			set_msg_attr(&attr[n_attr], IPUDP_A_TUN_PARAMS, p, 
					sizeof(*p), 0, &n_attr);
			break;

		}
		default: {
			ret_code = IPUDP_BAD_CMD_SPEC;	
			set_msg_attr(&attr[n_attr], IPUDP_A_RET_CODE, &ret_code, 
					sizeof(ret_code), 0, &n_attr);
			goto done;
		}
	}
		
done:
	return send_nl_msg(IPUDP_C_DEL, n_attr, MSG_REPLY, attr, info);
}

static int 
ipudp_genl_do_list(struct sk_buff *skb, struct genl_info *info){
	struct list_head * listp;	
	struct ipudp_nl_msg_attr *attr;	
	ipudp_nl_cmd_spec *cmd_spec;
	int n_attr = 0;
	__u32 ret_code;
	ipudp_nl_list_params *list_params;
	int ret;

	cmd_spec = (ipudp_nl_cmd_spec *)extract_nl_attr(info, IPUDP_A_CMD_SPEC);	
	list_params = (ipudp_nl_list_params *)extract_nl_attr(info, IPUDP_A_LIST_PARAMS);


	if ((!cmd_spec) || (!list_params)) {
		ret_code = IPUDP_BAD_MSG_FORMAT;
		attr = kmalloc(sizeof(*attr), GFP_KERNEL);
		set_msg_attr(&attr[n_attr], IPUDP_A_RET_CODE, 
				&ret_code, sizeof(ret_code), 0, &n_attr);
		goto done;	
	}


	switch(*cmd_spec){
		case CMD_S_VIFACE: 
		{	
			ipudp_dev *p;
			ipudp_dev_priv *priv;

			listp = ipudp_get_viface_list();	
			list_params->n_items = ipudp_get_viface_count();
			attr = kmalloc(sizeof(*attr) * (list_params->n_items + 2), GFP_KERNEL);
			
			ret_code = IPUDP_OK;
			set_msg_attr(&attr[n_attr], IPUDP_A_RET_CODE, 
					&ret_code, sizeof(ret_code), 0, &n_attr);
			set_msg_attr(&attr[n_attr], IPUDP_A_LIST_PARAMS, 
					list_params, sizeof(*list_params), 0, &n_attr);

			rcu_read_lock();
			list_for_each_entry_rcu(p, listp, list) {
					priv = netdev_priv(p->dev);
					set_msg_attr(&attr[n_attr], IPUDP_A_VIFACE_PARAMS, &priv->params, 
						sizeof(priv->params), 0, &n_attr);
			}
			rcu_read_unlock();
			break;
		}
		case CMD_S_TUN:
		{
			ipudp_list_tun_item *t;
			ipudp_dev_priv *priv = NULL;
			
			rcu_read_lock();
			priv = ipudp_get_priv(list_params->dev_name);
			
			if (!priv) {
				ret_code = IPUDP_ERR_DEV_NOT_FOUND;	
				attr = kmalloc(sizeof(*attr), GFP_KERNEL);
				set_msg_attr(&attr[n_attr], IPUDP_A_RET_CODE, &ret_code, 
					sizeof(ret_code), 0, &n_attr);
				rcu_read_unlock();
				goto done;
			}
			
				
			listp = &(priv->list_tun);
			list_params->n_items = priv->tun_count;
	
			attr = kmalloc(sizeof(*attr) * (list_params->n_items + 2), GFP_ATOMIC);
			
			ret_code = IPUDP_OK;
			set_msg_attr(&attr[n_attr], IPUDP_A_RET_CODE, 
				&ret_code, sizeof(ret_code), 0, &n_attr);
			set_msg_attr(&attr[n_attr], IPUDP_A_LIST_PARAMS, 
				list_params, sizeof(*list_params), 0, &n_attr);	
			
				
			list_for_each_entry(t, listp, list) {
				set_msg_attr(&attr[n_attr], IPUDP_A_TUN_PARAMS, &(t->tun), 
							sizeof(t->tun), 0, &n_attr);
			}
	
			rcu_read_unlock();

			break;
		}

		case CMD_S_RULE:
		{ 
			ipudp_dev_priv *priv = NULL;
			
			rcu_read_lock();
			priv = ipudp_get_priv(list_params->dev_name);
			
			if (!priv) {
				ret_code = IPUDP_ERR_DEV_NOT_FOUND;	
				attr = kmalloc(sizeof(*attr), GFP_KERNEL);
				set_msg_attr(&attr[n_attr], IPUDP_A_RET_CODE, &ret_code, 
					sizeof(ret_code), 0, &n_attr);
				rcu_read_unlock();
				goto done;
			}
			switch(priv->params.mode) {
				case MODE_MULTI_V4: {
					ipudp_rule_multi_v4 *t;

					listp = (struct list_head *)priv->fw_rules;
					
					list_params->n_items = priv->rule_count;
	
					attr = kmalloc(sizeof(*attr) * (list_params->n_items + 2), GFP_ATOMIC);
			
					ret_code = IPUDP_OK;
					set_msg_attr(&attr[n_attr], IPUDP_A_RET_CODE, 
						&ret_code, sizeof(ret_code), 0, &n_attr);
					set_msg_attr(&attr[n_attr], IPUDP_A_LIST_PARAMS, 
						list_params, sizeof(*list_params), 0, &n_attr);	
				
					list_for_each_entry(t, listp, list) {
							set_msg_attr(&attr[n_attr], IPUDP_A_RULE_PARAMS, t, 
															sizeof(*t), 0, &n_attr);
					}
		
					rcu_read_unlock();
					break;
				}
				default:
					ret_code = IPUDP_ERR_RULE_BAD_PARAMS;	
					attr = kmalloc(sizeof(*attr), GFP_KERNEL);
					set_msg_attr(&attr[n_attr], IPUDP_A_RET_CODE, &ret_code, 
						sizeof(ret_code), 0, &n_attr);
					rcu_read_unlock();
					goto done;
			}
			break;
		}	
		default: {
			ret_code = IPUDP_BAD_CMD_SPEC;
			attr = kmalloc(sizeof(*attr), GFP_KERNEL);
			set_msg_attr(&attr[n_attr], IPUDP_A_RET_CODE, 
				&ret_code, sizeof(ret_code), 0, &n_attr);
			break;
		}
	}

done:
	
	ret = send_nl_msg(IPUDP_C_LIST, n_attr, MSG_REPLY, attr, info);
	kfree(attr);
	return ret; 
}

/* end nl cmd callback */


/* genl_ops for each message type */
static struct 
genl_ops ipudp_gnl_ops_add = {
	.cmd = IPUDP_C_ADD,
	.flags = 0,
	.policy = ipudp_genl_policy,
	.doit = ipudp_genl_do_add,
	.dumpit = NULL,
};

static struct 
genl_ops ipudp_gnl_ops_del = {
	.cmd = IPUDP_C_DEL,
	.flags = 0,
	.policy = ipudp_genl_policy,
	.doit = ipudp_genl_do_del,
	.dumpit = NULL,
};

static struct 
genl_ops ipudp_gnl_ops_list = {
	.cmd = IPUDP_C_LIST,
	.flags = 0,
	.policy = ipudp_genl_policy,
	.doit = ipudp_genl_do_list,
	.dumpit = NULL,
};
/* end genl_ops */

int 
ipudp_genl_register(void){
	int err = 0;

	if ((err = genl_register_family(&ipudp_gnl_family)) != 0){
		printk("ipudp_genl_register: error registering genl family\n");
		return err;
	}

	if ((err = genl_register_ops(&ipudp_gnl_family, &ipudp_gnl_ops_add)) != 0)
		goto reg_err;
	if ((err = genl_register_ops(&ipudp_gnl_family, &ipudp_gnl_ops_del)) != 0)
		goto reg_err;
	if ((err = genl_register_ops(&ipudp_gnl_family, &ipudp_gnl_ops_list)) != 0)
		goto reg_err;
	/* TODO - register all ops */

	printk("ipudp_genl_register complete\n");
	return 0;


reg_err:
	printk("ipudp_genl_register: error registering ops\n");

	genl_unregister_family(&ipudp_gnl_family);
	return err;

}

void 
ipudp_genl_unregister(void){
	int err;

	err = genl_unregister_family(&ipudp_gnl_family);
	if (err != 0)
		printk("ipudp_genl_unregister: error unregistering genl family\n");
}


MODULE_LICENSE("GPL");
