#ifndef	_LIBCONFIG_H
#define	_LIBCONFIG_H

#define	LIBCONFIG_BUFSZ		1024
#define	LIBCONFIG_HTBL_SZ	17

__BEGIN_DECLS

extern const char *config_get(const char *, const char *);
extern int config_init(const char *);

__END_DECLS

#endif	/* _LIBCONFIG_H */

/*
 * Overrides for Emacs so that we follow Linus's tabbing style.
 * Emacs will notice this stuff at the end of the file and automatically
 * adjust the settings for this buffer only.  This must remain at the end
 * of the file.
 * ---------------------------------------------------------------------------
 * Local variables:
 * c-file-style: "linux"
 * End:
 */
