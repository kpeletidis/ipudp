#include "ipudp_client.h"


static int
load_dh_params(SSL_CTX *ctx,const char *file) {
    	DH *ret=0;
   	BIO *bio;

    	if ((bio=BIO_new_file(file,"r")) == NULL) {
      		print_log("Couldn't open DH file");
		return 0;
	}
    	
	ret=PEM_read_bio_DHparams(bio,NULL,NULL,NULL);
    	
	BIO_free(bio);
    	
	if(SSL_CTX_set_tmp_dh(ctx,ret)<0) {
      		print_log("Couldn't set DH parameters");
		return 0;
	}

	return 1;
}

int verify_cb(int preverify_ok, X509_STORE_CTX *x509_ctx) {
	/* put here something if needed */
    return preverify_ok;
}

SSL * 
ssl_ctx_init(void) {
	int fd = c_data.tcpfd;

	ssl_ctx = SSL_CTX_new(TLSv1_client_method());

	if (!SSL_CTX_set_cipher_list(ssl_ctx,CIPHER_LIST)) {
		print_log("SSL_CTX_set_cipher_list error\n");
		return NULL;
	}
    if(!(SSL_CTX_use_certificate_chain_file(ssl_ctx, CERTFILE))) {
		print_log("SSL_CTX_use_cert_chain error\n");
		return NULL;
	}
	if(!(SSL_CTX_use_PrivateKey_file(ssl_ctx, KEYFILE,
					SSL_FILETYPE_PEM))) {
		print_log("SSL_CTX_use_privatekey error\n");
		return NULL;
	}
    
	if (!SSL_CTX_check_private_key(ssl_ctx)) {
		printf("Private key does not match the certificate public key\n");
		return NULL;
	}

	if(!(SSL_CTX_load_verify_locations(ssl_ctx, 0, CAPATH))) {
		print_log("SSL_CTX_load_verify_loc error\n");
		return NULL;
	}

    if (!SSL_CTX_check_private_key(ssl_ctx)) {
        printf("Private key does not match the certificate public key\n");
        return NULL;
    }
	
	SSL_CTX_set_verify_depth (ssl_ctx, 3);
	SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, verify_cb);

	if (!(load_dh_params(ssl_ctx, DHFILE))) {
		print_log("Set DH params error\n");
		return NULL;
	}
	
	print_log("SSL context successfully initialized\n");
		
	ssl = SSL_new(ssl_ctx);

	
	if (ssl)
		SSL_set_fd(ssl, fd);
		
	return ssl;

}



int ssl_init(void) {
	char tmp_buf[1000];

	
	SSL_load_error_strings();
	SSL_library_init();
	RAND_seed((void *) tmp_buf, 1000);
	
	
//	bio_err=BIO_new_fp(stderr,BIO_NOCLOSE);
	

	print_log("ssl_init complete\n");

	if (!ssl_ctx_init()) 
		return -1;


	if (SSL_connect(ssl) != 1) {
		print_log("SSL_connect error\n");
		return -1;
  	}

	print_log("SSL handshake complete\n");


	return 0;
}


int
ssl_readline(SSL * fd, void *vptr, int maxlen, int * outlen)
{
	int	n, rc;
	char c, *ptr;

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
	*outlen= n - 1;

	return(rc);
}

int
ssl_write_n(SSL * ssl, unsigned char *buf, int len) {			
	int r;

	if ((r = SSL_write(ssl, buf, len)) <= 0) {
		print_log("write error\n");
	}

#ifdef DBG
	printf("ssl_write_n: %d bytes sent\nbuf: %s", r, buf);	
#endif
	return r;
}


int 
ssl_read_n(SSL *ssl, unsigned char *buf, int len) {
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
		print_log("SSL session shutdown\n");
		return -1;

	case SSL_ERROR_SYSCALL:
		print_log("SSL Error: Premature close\n");
		return -1;
	default:
		print_log("SSL read problem\n");
		return -1;
	}

}


void 
ssl_fini(void) {
	int ret;
	int err = 0;

	if (ssl){
_again:
		switch (ret = SSL_shutdown(ssl)) {
			case 1:
				break;
			case 0:
				if (err)	
					print_log("warning: SSL_shutdown failed\n");
				err = 1;
				goto _again;
			default:		
				print_log("warning: SSL_shutdown failed\n");
		}

		SSL_free(ssl);
	}
	
	if (ssl_ctx)
		SSL_CTX_free(ssl_ctx);

}
