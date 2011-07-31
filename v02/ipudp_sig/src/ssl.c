#include "ipudp_server.h"

#define KEYFILE "./certs/server.key"
#define CERTFILE "./certs/server.pem"
#define CAPATH "/etc/ssl/certs"
#define DHFILE "./certs/dh.pem"


void 
ssl_error(BIO *bio_err, const char *string) {
    BIO_printf(bio_err,"%s\n",string);
    ERR_print_errors(bio_err);
}


static int
load_dh_params(SSL_CTX *ctx,const char *file) {
	DH *ret=0;
   	BIO *bio;

	if ((bio=BIO_new_file(file,"r")) == NULL) {
      	if (verbose) printf("Couldn't open DH file");
		return 0;
	}
    	
	ret=PEM_read_bio_DHparams(bio,NULL,NULL,NULL);
    	
	BIO_free(bio);
    	
	if(SSL_CTX_set_tmp_dh(ctx,ret)<0) {
      	if (verbose) printf("Couldn't set DH parameters");
		return 0;
	}

	return 1;
}


int 
ssl_init(struct server_data *data) {
	char tmp_buf[1000];
	
	SSL_load_error_strings();
	SSL_library_init();
	RAND_seed((void *) tmp_buf, 1000);
	
	
	if (verbose) printf("ssl_init complete\n");

	return 0;
}


int
ssl_ctx_init(struct client_ctx *client, struct server_data *server) {
 	SSL *ssl_connection;
	SSL_CTX *ctx;
	
	SSL_library_init();
	SSL_load_error_strings();
	int ret = 0;

	ctx = SSL_CTX_new(TLSv1_server_method());

	if (!SSL_CTX_set_cipher_list(ctx, CIPHERLIST)) {
		if (verbose) printf("SSL_CTX_set_cipher_list error\n");
		ret = -1;
		goto ret_free_ctx;
	}

    if(!(SSL_CTX_use_certificate_chain_file(ctx, CERTFILE))) {
		if (verbose) printf("SSL_CTX_use_cert_chain error\n");
		ret = -1;
		goto ret_free_ctx;
	}
	if(!(SSL_CTX_use_PrivateKey_file(ctx, KEYFILE,
					SSL_FILETYPE_PEM))) {
		if (verbose) printf("SSL_CTX_use_privatekey error\n");
		ret = -1;
		goto ret_free_ctx;
	}

	if(!(SSL_CTX_load_verify_locations(ctx, 0, CAPATH))) {
		if (verbose) printf("SSL_CTX_load_verify_loc error\n");
		ret = -1;
		goto ret_free_ctx;
	}

	if (!(load_dh_params(ctx, DHFILE))) {
		if (verbose) printf("Set DH params error\n");
		ret = -1;
		goto ret_free_ctx;
	}	
	if (verbose) printf("SSL context successfully initialized\n");

	client->bio_err = BIO_new_fp(stderr,BIO_NOCLOSE);
		
	client->ssl = SSL_new(ctx);

	if (client->ssl)
		SSL_set_fd(client->ssl, client->afd);
	else {
		if (verbose) printf("SSL_new error\n");
		ret = -1;
		goto ret_free_ssl;
	}

	/* XXX register SSL socket handler into the mainloop */ 

	return ret;

ret_free_ssl:
	SSL_free(client->ssl);
	BIO_free(client->bio_err);
ret_free_ctx:
	SSL_CTX_free(client->ssl_ctx);

	return ret;
}


/*Very stupid and slow implementation of read line.
 * it's ok anyway....It does its work*/
int
ssl_readline(SSL * fd, void *vptr, int maxlen, int * outlen)
{
	int	n, rc;
	char	c, *ptr;

	ptr = vptr;
	for (n = 1; n < maxlen; n++) {
again:

		if ( (rc = SSL_read(fd, &c, 1)) == 1) {
			*ptr++ = c;
			if (c == '\n') 
				break;
		}

		else if (rc == 0) {
			*ptr = 0;
			*outlen= n - 1;	/* EOF, n - 1
					   bytes were read */
			return(rc);


		} else {
				
			if (errno == EINTR)
				goto again;

			
			return(rc);	/* error, errno 
					   set by read() */
		}
	}

	*ptr = 0;	/* null terminate like fgets() */

	return(rc);
}



void 
ssl_write_n(SSL * ssl, unsigned char *buf, int len) {
			
	int r;

	if ((r = SSL_write(ssl, buf, len)) <= 0) {
		if (verbose) printf("write error\n");
	}

	if (verbose) printf("ssl_write: %d bytes sent\n", r);
}

int 
ssl_read_n(SSL *ssl, unsigned char *buf, long len) {
	int ret; 
	unsigned char tmp[1000];
	int done = 0;
	unsigned char *p = buf;
	int l = 0;

	while(!done) {
		memset(tmp, 0, 1000);
		ret = SSL_read(ssl, tmp, 1000);

		if (ret > 0) {
			memcpy(p + l, tmp, ret);
			l = l + ret;
		}
		else 
			return ret;
		

		if (l == len)
			done = 1;
	}

	return l;
}


int
ssl_check_error(SSL * ssl, int ret) {
	switch(SSL_get_error(ssl, ret)){

	case SSL_ERROR_NONE:
		return 0;

	case SSL_ERROR_ZERO_RETURN:	
		if (verbose) printf("SSL session shutdown\n");
		return -1;

	case SSL_ERROR_SYSCALL:
		if (verbose) printf("SSL Error: Premature close\n");
		return -1;
	default:
		if (verbose) printf("SSL read problem\n");
		return -1;
	}

}

void 
ssl_client_fini(struct client_ctx *client) {
	
	/*
	SSL_close();
	SSL_CTX_free();
	SSL_free();	
	BIO_free();
	free(client);
	*/
	return; 
}

void ssl_fini(struct server_data *data) {
	return;
}
