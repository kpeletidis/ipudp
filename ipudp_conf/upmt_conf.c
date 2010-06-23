/*
 * upmtconf.c
 *
 *  Created on: 02/apr/2010
 *      Author: fabbox
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "upmt_user.h"

#define C_GET 1
#define C_ADD 2
#define C_DEL 3
#define C_LST 4
#define C_HAN 5
#define C_ECH 6
#define C_VRB 7
#define C_FSH 8

int op = 0;

void usage(){
	printf("\n USAGE\n");
	exit(-1);
}

void set_op(int operation){
	if(op == 0) op = operation;
	else usage();
}

void parse_number(int *n, char *string){
	*n = atoi(string);
	if(*n == 0) usage();
}

int main(int argc, char **argv){

	char *tun 			= NULL;
	char *iname			= NULL;
	char *rule 			= NULL;
	char *tsa 			= NULL;
	char *an 			= NULL;
	char *flush			= NULL;

	unsigned int local_address 		= 0;
	unsigned int local_port 		= 0;
	unsigned int remote_address 	= 0;
	unsigned int remote_port 		= 0;
	unsigned int inat_local_address 	= 0;
	unsigned int inat_remote_address	= 0;
	int tid 						= -1;
	int rid 						= -1;
	int ifindex 					= -1;
	int proto 						= -1;
	int mark 						= -1;
	int verbose						= -1;

	int command 					= -1;

	//./upmtconf -a tun -i eth0 -d 10.0.0.2 -l 1000 -r 2000 -n 1
	//./upmtconf -a rule -p udp -s 1.0.0.1 -d 1.0.0.2 -l 2000 -r 3000 -n 1

	//./upmtconf -g rule -p udp -s 10.0.0.1 -d 10.0.0.2 -l 10000 -r 20000
	//t


	int c;
	while((c = getopt(argc, argv, "a:g:x:i:d:l:r:n:p:s:f:h:m:M:eV:S:D:"))!= -1) {
		switch (c) {

			case 'e':
				set_op(C_ECH);
				break;

			case 'V':
				set_op(C_VRB);
				if(strcmp(optarg, "off") == 0) verbose = -1;
				else parse_number(&verbose, optarg);
				break;

			case 'a':
				if(strcmp(optarg, "tun") == 0) 			tun	 = optarg;
				else if(strcmp(optarg, "rule") == 0) 	rule = optarg;
				else if(strcmp(optarg, "tsa") == 0) 	tsa = optarg;
				else usage();
				set_op(C_ADD);
				break;

			case 'f':
				if(strcmp(optarg, "tun") == 0) 			flush = optarg;
				else if(strcmp(optarg, "rule") == 0) 	flush = optarg;
				else if(strcmp(optarg, "tsa") == 0) 	flush = optarg;
				else if(strcmp(optarg, "all") == 0) 	flush = optarg;
				else usage();
				set_op(C_FSH);
				break;

			case 'g':
				if(strcmp(optarg, "tun") == 0) 			tun	 = optarg;
				else if(strcmp(optarg, "rule") == 0) 	rule = optarg;
				else usage();
				set_op(C_GET);
				break;

			case 'x':
				if(strcmp(optarg, "tun") == 0) 			tun	 = optarg;
				else if(strcmp(optarg, "rule") == 0) 	rule = optarg;
				else usage();
				set_op(C_DEL);
				break;

			case 'm':
				if(strcmp(optarg, "an") == 0) 			an	 = optarg;
				else usage();
				break;

			case 'h':
				parse_number(&rid, optarg);
				set_op(C_HAN);
				break;

			case 'l':
				if(strcmp(optarg, "tun") == 0)			{ tun = optarg; 	set_op(C_LST); }
				else if(strcmp(optarg, "rule") == 0)	{ rule = optarg; 	set_op(C_LST); }
				else if(strcmp(optarg, "tsa") == 0)		{ tsa = optarg; 	set_op(C_LST); }
				else{
					local_port = atoi(optarg);
					if(local_port == 0) usage();
				}
				break;

			case 'i':
				iname = optarg;
				break;

			case 'd':
				if(inet_pton(AF_INET, optarg, &remote_address) != 1) usage();
				break;

			case 'S':
				if(strcmp(optarg, "off") == 0) break;
				if(inet_pton(AF_INET, optarg, &inat_local_address) != 1) usage();
				break;

			case 'D':
				if(strcmp(optarg, "off") == 0) break;
				if(inet_pton(AF_INET, optarg, &inat_remote_address) != 1) usage();
				break;

			case 'r':
				parse_number(&remote_port, optarg);
				break;

			case 'n':
				if(strcmp(optarg, "default") == 0) ifindex = 1111;
				else parse_number(&tid, optarg);
				break;

			case 'p':
				if(strcmp(optarg, "tcp") == 0) 			proto = 6;
				else if(strcmp(optarg, "udp") == 0) 	proto = 17;
				else usage();
				break;

			case 's':
				if(inet_pton(AF_INET, optarg, &local_address) != 1) usage();
				break;

			case 'M':
				parse_number(&mark, optarg);
				break;

			default:
				usage();
				break;
			}
	}

	struct tun_local tl = {
				.ifindex = -1,
				.port 	 = local_port
	};

	struct tun_remote tr = {
			.addr = remote_address,
			.port = remote_port
	};

	struct upmt_key key = {
			.proto = proto,
			.saddr = local_address,
			.daddr = remote_address,
			.sport = local_port,
			.dport = remote_port
	};

	struct tun_param tp = {
			.tid = tid,
			.tl = {
					.ifindex = ifindex,
					.port = local_port
			},
			.tr = {
					.addr = remote_address,
					.port = remote_port
			},
			.in = {
					.local = inat_local_address,
					.remote = inat_remote_address
			}
	};

	upmt_genl_client_init();

	if(op == C_FSH){
		send_flush_command(flush);
		receive_response();
	}

	if(op == C_VRB){
		send_verbose_command(verbose);
		receive_response();
	}

	if(op == C_ECH){
		send_echo_command();
		receive_response();
	}

	if(op == C_HAN){
		if(rid <= 0) usage();
		if(tid <= 0) usage();
		//printf("\n\t TID: %d", tid);
		//printf("\n\t RID: %d", rid);
		send_handover_command(rid, tid);
		receive_response();
		//parse_nl_attrs();
		//print_nl_attrs();
		//printResponse(UPMT_C_HANDOVER);
	}

	if(tsa != NULL){
		if(op == C_ADD){
			if((iname == NULL)||(local_port == 0)) usage();
			command = UPMT_C_SET_TSA;
			send_tsa_command(command, &tl, iname);
			printf("\n Sending set-tsa request...");
		}
		if(op == C_LST){
			command = UPMT_C_LST_TSA;
			send_tsa_command(command, NULL, NULL);
			printf("\n Sending lst-tsa request...");
		}
		receive_response();
	}

	if(tun != NULL){
		if(op == C_ADD){
			if((iname == NULL)||(local_port == 0)||(remote_address == 0)||(remote_port == 0)) usage();
			command = UPMT_C_SET_TUNNEL;
			send_tunt_command(command, iname, &tp);
			printf("\n Sending set-tun request...");
		}

		if(op == C_GET){
			if(tid <= 0) usage();
			command = UPMT_C_GET_TUNNEL;
			send_tunt_command(command, NULL, &tp);
			printf("\n Sending get-tun request...");
		}

		if(op == C_DEL){
			if(tid <= 0) usage();
			command = UPMT_C_DEL_TUNNEL;
			send_tunt_command(command, iname, &tp);
			printf("\n Sending del-tun request...");
		}

		if(op == C_LST){
			command = UPMT_C_LST_TUNNEL;
			send_tunt_command(command, NULL, NULL);
			printf("\n Sending lst-tun request...");
		}

		receive_response();
	}

	if(rule != NULL){
		if(op == C_ADD){
			if((proto < 0)||(local_address == 0)||(local_port == 0)||(remote_address == 0)||(remote_port == 0)||(tid == 0)) usage();
			command = UPMT_C_SET_RULE;
			send_paft_command(command, tid, rid, &key);
			printf("\n Sending set-rule request...");
		}

		if(op == C_GET){
			rid = tid;
			if(rid <= 0) usage();
			command = UPMT_C_GET_RULE;
			send_paft_command(command, -1, rid, &key);
			printf("\n Sending get-rule request...");
		}

		if(op == C_DEL){
			rid = tid;
			if(rid <= 0) usage();
			command = UPMT_C_DEL_RULE;
			send_paft_command(command, -1, rid, &key);
			printf("\n Sending del-rule request...");
		}

		if(op == C_LST){
			command = UPMT_C_LST_RULE;
			send_paft_command(command, -1, -1, NULL);
			printf("\n Sending lst-rule request...");
		}

		receive_response();
	}

	if(an != NULL){
		if(mark < 0) usage();
		send_an_command(mark);
		receive_response();
	}

	printf("\n\n");
	return 0;
}
