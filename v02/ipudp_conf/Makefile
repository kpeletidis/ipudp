RM = rm
CC = gcc

IPDUP_KERNEL_DIR = ../ipudp_mod/
PROG = ipudp_conf
OBJS = ipudp_genl.o ipudp_conf.o ipudp_util.o
 
CFLAGS += -Wall -ggdb -DDEBUG -DUSERSPACE
LIBS += 
INCFLAGS += -I$(IPDUP_KERNEL_DIR)

all: $(OBJS)
	$(CC) $(OBJS) $(LIBS) -o $(PROG)

%.o: %.c
	$(CC) -c $(CFLAGS) $(INCFLAGS) -o $@ $<


#.SILENT: clean
.PHONY: clean

clean:	
	$(RM) $(PROG) $(OBJS)
