#include "ipudp_client.h"

void 
print_log(char *p) {
	if(verbose)
		fprintf(stderr,"%s", p);	
	else
		;
}

/*
void 
test_send() {
	unsigned char *buf="ciao\n";
	ssl_write_n(ssl, buf, 5);
	sleep(5);	
	sendto(c_data.udpfd, (void *)buf, 5, 0,(struct sockaddr *)&c_data.udp_server, sizeof(struct sockaddr_in));
	sleep(5);	
	return;
}*/
