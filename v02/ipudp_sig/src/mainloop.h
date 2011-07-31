#ifndef _MAIN_LOOP_H
#define _MAIN_LOOP_H

#define MAINLOOP_ALL_CTX (void *) -1

#define time_before(a, b) \
	((a)->sec < (b)->sec || \
	 ((a)->sec == (b)->sec && (a)->usec < (b)->usec))

#define time_sub(a, b, res) do { \
	(res)->sec = (a)->sec - (b)->sec; \
	(res)->usec = (a)->usec - (b)->usec; \
	if ((res)->usec < 0) { \
		(res)->sec--; \
		(res)->usec += 1000000; \
	} \
} while (0)

typedef long os_time_t;

typedef enum {
	EVENT_TYPE_READ = 0,
	EVENT_TYPE_WRITE,
	EVENT_TYPE_EXCEPTION
} mainloop_event_type;

struct os_time {
    os_time_t sec;
    os_time_t usec;
};

typedef void (*mainloop_sock_handler)(int sock, void *mainloop_ctx, void *sock_ctx);
typedef void (*mainloop_timeout_handler)(void *mainloop_data, void *user_ctx);
typedef void (*mainloop_signal_handler)(int sig, void *mainloop_ctx, void *signal_ctx);

typedef void (*mainloop_event_handler)(void *mainloop_data, void *user_ctx);

int mainloop_register_sock(int, mainloop_event_type, 
				mainloop_sock_handler, void *, void *);

void mainloop_unregister_sock(int, mainloop_event_type);

int mainloop_register_timeout(unsigned int, unsigned int,
				mainloop_timeout_handler, void *, void *);
int mainloop_cancel_timeout(mainloop_timeout_handler, void *, void *);

int mainloop_init(void *);

void mainloop_terminate(void);

void mainloop_run (void);
void mainloop_destroy (void);

int os_get_time(struct os_time *);

#endif

