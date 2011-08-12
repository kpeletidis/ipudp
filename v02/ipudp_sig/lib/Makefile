# Non-optional:
#LINUXSRC= /usr/src/linux-2.6.11.7-um
#LINUXSRC= /usr/src/linux-2.6.9

# Optional:
#KERNEL_EXTRA= ARCH=um  # you must enable this if building for UML

prefix=/usr/
PREFIXLIB= $(prefix)/lib
PREFIXINC= $(prefix)/include

# Enable for debugging
#DEBUG_POLICY= DEBUG
#DEBUG_POLICY= NO_DEBUG

# Don't touch this...
USE_THREADS=n
USE_READLINE=y

LIB= appconsole
VERSION= 1
OBJS= appconsole.o vers
INC= appconsole.h
TESTS= test

ifeq ($(USE_THREADS),y)
LDLIBS= -lpthread
endif

ifeq ($(USE_READLINE),y)
LDLIBS += -lreadline -lcurses
endif

include Makefile.lib
