SERVERPROG = server
CLIENTPROG = client

CLIENTOBJS = mainloop.o ssl.o client.o
SERVEROBJS = server_main.o mainloop.o ssl.o server.o proto.o 

SERVERHEADER = ipudp_server.h list.h mainloop.h
CFLAGS += -Wall -ggdb -DDBG

INCFLAGS =
CLIENTLIBS = -lssl
SERVERLIBS = -lssl 

all: server

#client: $(CLIENTOBJS)
#	gcc $(CFLAGS) -DCLIENT $(CLIENTOBJS) $(CLIENTLIBS) -o $(CLIENTPROG)

server: $(SERVEROBJS) $(SERVERHEADER)
	gcc $(CFLAGS) -DSERVER $(SERVEROBJS) $(SERVERLIBS) -o $(SERVERPROG)

.SILENT:clean

clean:
	rm -f *.o $(CLIENTPROG) $(SERVERPROG)
