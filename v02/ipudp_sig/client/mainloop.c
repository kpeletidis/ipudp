#include "ipudp_client.h"

struct 
mainloop_sock_table {
	int count;
	struct mainloop_sock *table;
	int changed;
};

struct 
mainloop_sock {
	int sock;	
	void *mainloop_data;
	void *user_data;
	mainloop_sock_handler handler;
};

struct 
mainloop_timeout {
	struct os_time time;
	void *mainloop_data;
	void *user_data;
	mainloop_timeout_handler handler;
	struct mainloop_timeout *next;
};

struct 
mainloop_signal {
        int sig;
        void *user_data;
        mainloop_signal_handler handler;
        int signaled;
};



struct 
mainloop_data {
	void *user_data;

	int max_sock;

	struct mainloop_sock_table readers;
	struct mainloop_sock_table writers;
	struct mainloop_sock_table exceptions;

	struct mainloop_timeout *timeout;
	
	int exitloop;
	
	int signal_count;
	struct mainloop_signal *signals;
	int signaled;
	int pending_terminate;
	int terminate;
};


static struct mainloop_data mainloop;


void mainloop_terminate()
{
	mainloop.terminate = 1;
}

static void mainloop_process_pending_signals(void) {
        int i;

        if (mainloop.signaled == 0)
                return;
        mainloop.signaled = 0;

        if (mainloop.pending_terminate) {
                mainloop.pending_terminate = 0;
        }

        for (i = 0; i < mainloop.signal_count; i++) {
                if (mainloop.signals[i].signaled) {
                        mainloop.signals[i].signaled = 0;
                        mainloop.signals[i].handler(mainloop.signals[i].sig,
                                                 mainloop.user_data,
                                                 mainloop.signals[i].user_data);
                }
        }
}
int 
mainloop_init(void *user_data)
{
	memset(&mainloop, 0, sizeof(mainloop));

	if (user_data != NULL)
		mainloop.user_data = user_data;

	return 0;
}

static int 
mainloop_sock_table_add_sock(struct mainloop_sock_table *table,
                                     int sock, mainloop_sock_handler handler,
                                     void *mainloop_data, void *user_data)
{
	struct mainloop_sock *tmp;

	if (table == NULL)
		return -1;

	tmp = (struct mainloop_sock *)
		realloc(table->table,
			   (table->count + 1) * sizeof(struct mainloop_sock));
	if (tmp == NULL)
		return -1;
	
	tmp[table->count].sock = sock;
	tmp[table->count].mainloop_data = mainloop_data;
	tmp[table->count].user_data = user_data;
	tmp[table->count].handler = handler;
	table->count++;
	table->table = tmp;
	if (sock > mainloop.max_sock)
		mainloop.max_sock = sock;
	table->changed = 1;

	return 0;
}



static void 
mainloop_sock_table_remove_sock(struct mainloop_sock_table *table,
                                         int sock)
{
	int i;

	if (table == NULL || table->table == NULL || table->count == 0)
		return;

	for (i = 0; i < table->count; i++) {
		if (table->table[i].sock == sock)
			break;
	}
	if (i == table->count)
		return;
	if (i != table->count - 1) {
		memmove(&table->table[i], &table->table[i + 1],
			   (table->count - i - 1) *
			   sizeof(struct mainloop_sock));
	}
	table->count--;
	table->changed = 1;
}


static void mainloop_sock_table_set_fds(struct mainloop_sock_table *table,
				     fd_set *fds)
{
	int i;

	FD_ZERO(fds);

	if (table->table == NULL)
		return;

	for (i = 0; i < table->count; i++)
		FD_SET(table->table[i].sock, fds);
}


static void mainloop_sock_table_dispatch(struct mainloop_sock_table *table,
				      fd_set *fds)
{
	int i;

	if (table == NULL || table->table == NULL)
		return;

	table->changed = 0;
	for (i = 0; i < table->count; i++) {
		if (FD_ISSET(table->table[i].sock, fds)) {
			table->table[i].handler(table->table[i].sock,
						table->table[i].mainloop_data,
						table->table[i].user_data);
			if (table->changed)
				break;
		}
	}
}


static void mainloop_sock_table_destroy(struct mainloop_sock_table *table)
{
	if (table)
		free(table->table);
}

int mainloop_register_read_sock(int sock, mainloop_sock_handler handler,
			     void *mainloop_data, void *user_data)
{
	return mainloop_register_sock(sock, EVENT_TYPE_READ, handler,
				   mainloop_data, user_data);
}


void mainloop_unregister_read_sock(int sock)
{
	mainloop_unregister_sock(sock, EVENT_TYPE_READ);
}


static struct mainloop_sock_table *mainloop_get_sock_table(mainloop_event_type type)
{
	switch (type) {
	case EVENT_TYPE_READ:
		return &mainloop.readers;
	case EVENT_TYPE_WRITE:
		return &mainloop.writers;
	case EVENT_TYPE_EXCEPTION:
		return &mainloop.exceptions;
	}

	return NULL;
}

int mainloop_register_sock(int sock, mainloop_event_type type,
			mainloop_sock_handler handler,
			void *mainloop_data, void *user_data)
{
	struct mainloop_sock_table *table;

	table = mainloop_get_sock_table(type);
	return mainloop_sock_table_add_sock(table, sock, handler,
					 mainloop_data, user_data);
}


void mainloop_unregister_sock(int sock, mainloop_event_type type)
{
	struct mainloop_sock_table *table;

	table = mainloop_get_sock_table(type);
	mainloop_sock_table_remove_sock(table, sock);
}




void mainloop_run (void) {
	
	fd_set *rfds, *wfds, *efds;
	int res;
	struct timeval _tv;
	struct os_time tv, now;

	rfds = malloc(sizeof(*rfds));
	wfds = malloc(sizeof(*wfds));
	efds = malloc(sizeof(*efds));


	if (verbose) printf("running main loop\n");

	if (rfds == NULL || wfds == NULL || efds == NULL) {
		printf("mainloop_run - malloc failed\n");
		goto out;
	}

	while (!mainloop.terminate &&
	       (mainloop.timeout || mainloop.readers.count > 0 ||
		mainloop.writers.count > 0 || mainloop.exceptions.count > 0)) {
		if (mainloop.timeout) {
			os_get_time(&now);
			if (time_before(&now, &mainloop.timeout->time))
				time_sub(&mainloop.timeout->time, &now, &tv);
			else
				tv.sec = tv.usec = 0;
#if 0
			printf("next timeout in %lu.%06lu sec\n",
			       tv.sec, tv.usec);
#endif
			_tv.tv_sec = tv.sec;
			_tv.tv_usec = tv.usec;
		}

		mainloop_sock_table_set_fds(&mainloop.readers, rfds);
		mainloop_sock_table_set_fds(&mainloop.writers, wfds);
		mainloop_sock_table_set_fds(&mainloop.exceptions, efds);
		res = select(mainloop.max_sock + 1, rfds, wfds, efds,
			     mainloop.timeout ? &_tv : NULL);
		if (res < 0 && errno != EINTR && errno != 0) {
			perror("select");
			goto out;
		}
		mainloop_process_pending_signals();

		/* check if some registered timeouts have occurred */
		if (mainloop.timeout) {
			struct mainloop_timeout *tmp;

			os_get_time(&now);
			if (!time_before(&now, &mainloop.timeout->time)) {
				tmp = mainloop.timeout;
				mainloop.timeout = mainloop.timeout->next;
				tmp->handler(tmp->mainloop_data,
					     tmp->user_data);
				free(tmp);
			}

		}

		if (res <= 0)
			continue;

		mainloop_sock_table_dispatch(&mainloop.readers, rfds);
		mainloop_sock_table_dispatch(&mainloop.writers, wfds);
		mainloop_sock_table_dispatch(&mainloop.exceptions, efds);
	}

out:
	free(rfds);
	free(wfds);
	free(efds);
}


int mainloop_register_timeout(unsigned int secs, unsigned int usecs,
			   mainloop_timeout_handler handler,
			   void *mainloop_data, void *user_data)
{
	struct mainloop_timeout *timeout, *tmp, *prev;

	timeout = malloc(sizeof(*timeout));
	if (timeout == NULL)
		return -1;
	os_get_time(&timeout->time);
	timeout->time.sec += secs;
	timeout->time.usec += usecs;
	while (timeout->time.usec >= 1000000) {
		timeout->time.sec++;
		timeout->time.usec -= 1000000;
	}
	timeout->mainloop_data = mainloop_data;
	timeout->user_data = user_data;
	timeout->handler = handler;
	timeout->next = NULL;

	if (mainloop.timeout == NULL) {
		mainloop.timeout = timeout;
		return 0;
	}

	prev = NULL;
	tmp = mainloop.timeout;
	while (tmp != NULL) {
		if (time_before(&timeout->time, &tmp->time))
			break;
		prev = tmp;
		tmp = tmp->next;
	}

	if (prev == NULL) {
		timeout->next = mainloop.timeout;
		mainloop.timeout = timeout;
	} else {
		timeout->next = prev->next;
		prev->next = timeout;
	}

	return 0;
}

int mainloop_cancel_timeout(mainloop_timeout_handler handler,
			 void *mainloop_data, void *user_data)
{
	struct mainloop_timeout *timeout, *prev, *next;
	int removed = 0;

	prev = NULL;
	timeout = mainloop.timeout;
	while (timeout != NULL) {
		next = timeout->next;

		if (timeout->handler == handler &&
		    (timeout->mainloop_data == mainloop_data ||
		     mainloop_data == MAINLOOP_ALL_CTX) &&
		    (timeout->user_data == user_data ||
		     user_data == MAINLOOP_ALL_CTX)) {
			if (prev == NULL)
				mainloop.timeout = next;
			else
				prev->next = next;
			free(timeout);
			removed++;
		} else
			prev = timeout;

		timeout = next;
	}

	return removed;
}

int os_get_time(struct os_time *t)
{
        int res;
        struct timeval tv;
        res = gettimeofday(&tv, NULL);
        t->sec = tv.tv_sec;
        t->usec = tv.tv_usec;
        return res;
}

void mainloop_destroy(void)
{
    struct mainloop_timeout *timeout, *prev;

    timeout = mainloop.timeout;
    while (timeout != NULL) {
        prev = timeout;
        timeout = timeout->next;
        free(prev);
    }
    mainloop_sock_table_destroy(&mainloop.readers);
    mainloop_sock_table_destroy(&mainloop.writers);
    mainloop_sock_table_destroy(&mainloop.exceptions);
    free(mainloop.signals);
}
