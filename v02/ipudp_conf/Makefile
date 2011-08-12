RM = rm
CC = gcc
AR = ar rcs

IPDUP_KERNEL_DIR = ../ipudp_mod/
PROG = ipudp_conf
LIB = libipudp_conf.a
OBJS = ipudp_genl.o ipudp_conf.o ipudp_util.o
LIBOBJS = ipudp_genl.o ipudp_util.o
 
CFLAGS += -Wall -ggdb -DDEBUG -DUSERSPACE
LIBS += 
INCFLAGS += -I$(IPDUP_KERNEL_DIR)

all: $(OBJS)
	$(CC) $(OBJS) $(LIBS) -o $(PROG)

%.o: %.c
	$(CC) -c $(CFLAGS) $(INCFLAGS) -o $@ $<

lib: $(LIBOBJS)
	$(AR) $(LIB) $(LIBOBJS)

.SILENT: clean

clean:	
	$(RM) $(PROG) $(OBJS) $(LIB)
