PROG = client

OBJS = mainloop.o ssl.o client.o console.o client_main.o utils.o proto.o ipudp_conf.o tunnel.o

HEADERS = ipudp_client.h list.h mainloop.h
CFLAGS += -Wall  -I../ipudp_conf/ -I../lib -I../../ipudp_mod/ -DDBG -DUSERSPACE

DEPLIB = -L../libs/ -lappconsole -Wl,-rpath,../libs/ 
LIBS = $(DEPLIB) -lssl  -L../lib/ -lipudp_conf

all: client

client: $(OBJS) $(HEADERS)
	gcc $(CFLAGS) $(OBJS) $(LIBS) -o $(PROG)


%.o: %.c
	$(CC) -c $(CFLAGS) -o $@ $<

.SILENT:clean

clean:
	rm -f *.o $(PROG) $(OBJS)
