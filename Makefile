CC      = gcc
CFLAGS  = -Wall -g -D_GNU_SOURCE -D_DEFALUT_SOURCE -std=c99 -Werror -pedantic

.SUFFIXES: .c .o

.PHONY: all clean

all: cping
clean:
	rm -rf *.o cping

cping: cping.o utils.o

cping.o: utils.o
utils.o: utils.h 


