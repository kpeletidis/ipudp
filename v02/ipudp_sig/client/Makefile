PROG = client

OBJS = mainloop.o ssl.o client.o console.o client_main.o utils.o proto.o ipudp_conf.o

HEADERS = ipudp_client.h list.h mainloop.h
CFLAGS += -Wall -Ilib/ -DDBG

DEPLIB = -L.libs/ -lappconsole -Wl,-rpath,.libs/ 
LIBS = $(DEPLIB) -lssl 

all: client

client: $(OBJS) $(HEADERS)
	gcc $(CFLAGS) $(OBJS) $(LIBS) -o $(PROG)


%.o: %.c
	$(CC) -c $(CFLAGS) -o $@ $<

.SILENT:clean

clean:
	rm -f *.o $(PROG) $(OBJS)
