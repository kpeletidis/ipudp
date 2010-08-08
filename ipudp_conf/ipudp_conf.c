
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <string.h>

#include "ipudp_conf.h"
#include <ipudp.h>

void usage(){
	printf( "Usage: ipudp_conf -cmd_arg <cmd_opt>\n"
		"Possible cmd_arg: ADD (-a) DEL (-d) GET (-g) LIST (-l)\n"
		"Possible cmd_opt: args: dev, tun, rule, tsa\n"
	);
	exit(-1);
}

void usage_dev() {
	printf(	"dev help:\n"
		"add ipudp virtual interface:\n"
		"ipudp_conf -a dev -N <dev_name> "
		"-M <fixed|multi_v4> -P <v4|v6>\n"
		"del ipudp virtual interface:\n"
		"ipudp_conf -d dev -N <dev_name>\n"
	);
	exit(-1);
}

void usage_tun() {
	printf( "tun help:\n"
		"add ipudp tunnel:\n"
		"ipudp_conf -a tun -N <viface_name> -T <mark> "
		"-P <v4|v6> -D <ip_dest> -S <ip_source> -L <locl_port> "
		"-R <remote_port> -I <tun_id> -U <tun_real_dev>\n"
		"del ipudp tunnel:\n"
		"ipudp_conf -d tun -N <viface_name> -I <tun_id>\n"
	);
	exit(-1);
}

void usage_tsa() {
	printf( "tun help:\n"
		"add ipudp tsa:\n"
		"ipudp_conf -d tsa -N <viface_name> -K <inode>\n"
	);
	exit(-1);
}

void usage_rule() {
	printf( "rule help:\n"
		"add ipudp rule:\n"
		"ipudp_conf -a rule -N <viface_name> -M <mode> -I <tid> [mode specific rule]\n"
		"Rules:\n"
		"For MODE_MULTI_V4 set the destination address of the rule with -D <ip_addr>\n"
	);
	exit(-1);
}
void usage_list() {
	printf( "list help:\n"
		"ipudp_conf -l <type> [-N <dev_name>] \n"
		"Possible type: dev, tun, rule, tsa\n"
		"-N option is mandatory in all cases except \"-l dev\"\n" 
	);
	exit(-1);
}

int 
main(int argc, char **argv){
	ipudp_genl_cmd cmd = -1;
	int cmd_attr = 0;
	char *viface_name = NULL;
	char *dev_name = NULL;
	u32 mark = 0; 
	ipudp_viface_mode viface_mode = MODE_FIXED;
	ipudp_af_inet ip_vers = IPV4;
	char *src_addr = NULL;
	u16 local_port = 0;
	char *dest_addr = NULL;
	u16 remote_port = 0;	
	int tid = -1;
	u32 rule_id = 0;
	unsigned long inode = 0;
	int c;
	int ret;

	while((c = getopt(argc, argv, "a:d:s:l:R:L:S:D:N:U:M:T:P:I:K:J:"))!= -1) {
		switch (c) {
			case 'a':
				cmd = IPUDP_C_ADD;
				if (!strcmp(optarg, "tun"))
					cmd_attr = TUN;
				else if (!strcmp(optarg, "rule"))	
					cmd_attr = RULE;
				else if (!strcmp(optarg, "tsa"))
					cmd_attr = TSA;
				else if (!strcmp(optarg, "dev"))
					cmd_attr = VIFACE;

				else usage();
				break;
			case 'd':
				cmd = IPUDP_C_DEL;
				if (!strcmp(optarg, "tun"))
					cmd_attr = TUN;
				else if (!strcmp(optarg, "rule"))	
					cmd_attr = RULE;
				else if (!strcmp(optarg, "tsa"))
					cmd_attr = TSA;
				else if (!strcmp(optarg, "dev"))
					cmd_attr = VIFACE;

				else usage();
				break;
			case 'l':
				cmd = IPUDP_C_LIST;
				if (!strcmp(optarg, "tun"))
					cmd_attr = TUN;
				else if (!strcmp(optarg, "rule"))	
					cmd_attr = RULE;
				else if (!strcmp(optarg, "tsa"))
					cmd_attr = TSA;
				else if (!strcmp(optarg, "dev"))
					cmd_attr = VIFACE;
	
				else usage_list();
				break;	
			case 'N':
				viface_name = optarg;	
				if ((strlen(viface_name) > MAX_IPUDP_DEV_NAME_LEN)){
					printf("viface name too long\n");
					exit(-1);
				}	

				break;		
			case 'U':
				dev_name = optarg;
				break;
			case 'M':	
				if (!strcmp(optarg, "fixed"))
					viface_mode = MODE_FIXED;	
				else if (!strcmp(optarg, "multi_v4"))
					viface_mode = MODE_MULTI_V4;
				else {
					printf("error: option -M arg can be: (fixed|multi_app_v4)\n");
					exit(-1);
				}	
				break;
			case 'T':
				mark = (u32) atoi(optarg);
				break;
			case 'P':
				if (!strncmp(optarg, "v4",2))
					ip_vers = IPV4;	
				else if (!strncmp(optarg, "v6",2))	
					ip_vers = IPV6;	
				else {
					printf("error: option -P arg can be: (v4|v6)\n");
					exit(-1);
				}
				break;	
			case 'D':
				dest_addr = optarg;	
				break;		
			case 'S':
				src_addr = optarg;
				break;		
			case 'R':
				remote_port = (u16)atoi(optarg);
				break;
			case 'L':
				local_port = (u16)atoi(optarg);
				break;
			case 'I':
				tid = (u32)atoi(optarg);
				break;
			case 'K':
				inode = (unsigned long)atol(optarg);
				break;	
			case 'J':
				rule_id = (u32)atoi(optarg);
				break;	

			default:
				usage();
				break;
			}
	}

	if (ipudp_genl_client_init() < 0) {
		printf("ipudp_genl_client_init error\n");
		exit(-1);
	}
		
	switch (cmd) {
		case IPUDP_C_ADD:
			if (cmd_attr == RULE) {	
				ipudp_viface_params p;
				void *rp = NULL;
				int size = 0;

				if (!viface_name) { 
					printf("error: a viface must be specified\n");
					usage_rule();	
				}
				memcpy(p.name, viface_name, MAX_IPUDP_DEV_NAME_LEN);

				if (!viface_mode) { 
					printf("error: bad viface mode\n");
					usage_rule();	
				}
				
				if (tid < 0) { 
					printf("error: a tunnel id must be specified\n");
					usage_rule();	
				}
				//parse rule parameters
				if (viface_mode == MODE_MULTI_V4) {

						ipudp_rule_multi_v4 rule;
						u32 daddr_bin;
						
						memset(&rule,0,sizeof(rule));
					
						rule.type = viface_mode;
						rule.tun_id = tid;

						if (dest_addr) {
							if (inet_pton(AF_INET, dest_addr, &daddr_bin) <= 0) {
								printf("error: expected valid ipv4 destination address\n");
								usage_rule();	
							}	
							rule.dest = daddr_bin;
						}			
						else {
							printf("error: destination address must be specified\n");
							usage_rule();	
						}

						rp = &rule;
						size = sizeof(ipudp_rule_multi_v4);
				}
				else {
						printf("Unsupported viface mode\n");
						usage_rule();
				}
				ret = do_cmd_add_rule(&p, rp, size);

			}	
			else if (cmd_attr == TSA)
				/*TODO*/;
			else if (cmd_attr == VIFACE)
			{
					
				ipudp_viface_params p;
				memset(&p,0,sizeof(p));
	
				if (viface_name) { 
					memset(p.name,0, MAX_IPUDP_DEV_NAME_LEN);
					memcpy(p.name, viface_name, strlen(viface_name));
				}
	
				p.mode = viface_mode;
				p.af_out = ip_vers;

				ret = do_cmd_add_viface(&p);
			}

			else if (cmd_attr == TUN) 
			{
				ipudp_viface_params viface_params;
				ipudp_tun_params tun_params;
				u8 saddr_bin[16]; //also for v4        
				u8 daddr_bin[16]; //also for v4
				int iface_idx;
	
				memset(&viface_params,0,sizeof(viface_params));
				memset(&tun_params,0,sizeof(tun_params));
				
				if (!viface_name){	
					printf("error: a viface must be specified\n");
					usage_tun();	
				}

				memcpy(viface_params.name, viface_name, strlen(viface_name));
				
				if (!ip_vers) {
					printf("error: tun ip version must be specified\n");
					usage_tun();	
				}
				tun_params.af = ip_vers;

				//parse tun source address
				if (src_addr) {
					if (ip_vers == IPV4){	
						if (inet_pton(AF_INET, src_addr, saddr_bin) <= 0) {
							printf("error: expected valid ipv4 tun source address\n");
							usage_tun();	
						}	
						memcpy(&(tun_params.u.v4p.src),saddr_bin,4);
					}
					else {
						if (inet_pton(AF_INET6, src_addr, saddr_bin) <= 0){	
							printf("error: expected valid ipv6 tun source address\n");
							usage_tun();	
						}
						memcpy(tun_params.u.v6p.src,saddr_bin,16);
					}
				}

				if ((!src_addr) && (!dev_name)) {
					printf("error: a real device name must be indicated to add tunnel when src address missing\n");
					usage_tun();	
				}

				if (dev_name) {
					if((iface_idx = get_iface_idx_by_name(dev_name))<1) {
						printf("error: dev %s not found or you must be root\n", dev_name);
						usage_tun();	
					}
					tun_params.dev_idx = iface_idx;
				}

				//parse tun dest address
				if (dest_addr) {
					if (ip_vers == IPV4){	
						if (inet_pton(AF_INET, dest_addr, daddr_bin) <= 0) {
							printf("error: expected valid ipv4 tun destination address\n");
							usage_tun();	
						}	
						memcpy(&(tun_params.u.v4p.dest),daddr_bin,4);
					}
					else {
						if (inet_pton(AF_INET6, dest_addr, daddr_bin) <= 0){	
							printf("error: expected valid ipv6 tun destination address\n");
							usage_tun();	
						}
						memcpy(tun_params.u.v6p.dest,daddr_bin,16);
					}
				}			
				else {
					printf("error: tun destination address must be specified\n");
					usage_tun();	
				}
				
				if (local_port)
					tun_params.srcport = htons(local_port);
				else {
					//even though it is not strictly necessary we prefer
					//to allow only specified local port.. for now TODO
					printf("error: tun local port must be specified\n");
					usage_tun();	
				}
				if (remote_port)
					tun_params.destport = htons(remote_port);			
				else {
					printf("error: tun remote port must be specified\n");
					usage_tun();	
				}
				if (mark)		
					tun_params.mark = mark;
				if (tid < 0) 
					tun_params.tid = 0;
				else 
					tun_params.tid = tid;
				
				ret = do_cmd_add_tun(&viface_params, &tun_params);
			}				
			break;

		case IPUDP_C_DEL:
			if (cmd_attr == RULE){
				ipudp_rule p;
				ipudp_viface_params q;

				if (!viface_name){
					printf("ipudp viface name must be specified\n");
					usage_tsa();
				}
				else {
					memset(&q,0,sizeof(q));	
					memset(q.name,0, MAX_IPUDP_DEV_NAME_LEN);
					memcpy(q.name, viface_name, strlen(viface_name));
				}
			
				if (!rule_id) {
					printf("rule id must be specified\n");
					usage_rule();
				}	
				else 
					p.id = rule_id;
				
				ret = do_cmd_del_rule(&q, &p);
			}
			else if (cmd_attr == TSA){
				ipudp_tsa_params p;
				ipudp_viface_params q;

				if (!viface_name){
					printf("ipudp viface name must be specified\n");
					usage_tsa();
				}
				else {
					memset(&q,0,sizeof(q));	
					memset(q.name,0, MAX_IPUDP_DEV_NAME_LEN);
					memcpy(q.name, viface_name, strlen(viface_name));
				}
			
				if (!inode) {
					printf("inode number must be specified\n");
					usage_tsa();
				}	
				else 
					p.ino = inode;
				
				ret = do_cmd_del_tsa(&q, &p);
			}
			else if (cmd_attr == VIFACE){
					
				ipudp_viface_params p;
					
				if (!viface_name){
					printf("ipudp viface name must be specified\n");
					usage_dev();
				}
				memset(&p,0,sizeof(p));
	
				if (viface_name) {
					memset(p.name,0, MAX_IPUDP_DEV_NAME_LEN);
					memcpy(p.name, viface_name, strlen(viface_name));
				}
				else {
					printf("Viface name required\n");
					usage_dev();
				}

				ret = do_cmd_del_viface(&p);
			}
			else if (cmd_attr == TUN) {
				ipudp_tun_params p;
				ipudp_viface_params q;
				

				if (!viface_name){
					printf("ipudp viface name must be specified\n");
					usage_tun();
				}
				else {
					memset(&q,0,sizeof(q));	
					memset(q.name,0, MAX_IPUDP_DEV_NAME_LEN);
					memcpy(q.name, viface_name, strlen(viface_name));
				}
			
				if (tid < 0) {
					printf("tunnel id must be specified\n");
					usage_tun();
				}	
				else 
					p.tid = tid;
				
				ret = do_cmd_del_tun(&q, &p);
			}
				
			break;

		case IPUDP_C_LIST:

			if (cmd_attr != VIFACE) {
					if (!viface_name){
					printf("ipudp viface name must be specified\n");
					usage_list();
				}
			}

			ret = do_cmd_list(viface_name, cmd_attr);
					printf("error getting list\n");
			break;	

		default:
			printf("error: no command specified\n");
			usage();
			break;
	}

	return ret;
}
