SERVERPROG = server

SERVEROBJS = server_main.o mainloop.o ssl.o server.o proto.o ipudp_conf.o tunnel.o 

SERVERHEADER = ipudp_server.h list.h mainloop.h
CFLAGS += -Wall -ggdb -DDBG -DUSERSPACE -I../../ipudp_mod/  -I../lib

INCFLAGS =
SERVERLIBS = -lssl  -L../lib/ -lipudp_conf

all: server

server: $(SERVEROBJS) $(SERVERHEADER)
	gcc $(CFLAGS) -DSERVER $(SERVEROBJS) $(SERVERLIBS) -o $(SERVERPROG)

.SILENT:clean

clean:
	rm -f *.o $(SERVERPROG)
