EXECUTABLE=lpsd
BUILDDIR=
OBJDIR=obj

CC=gcc
SRC=lpsd.c
IDIR=
LIBS=

CFLAGS=-Wall -std=gnu17 -O2

all: lpsd

$(EXECUTABLE): $(SRC)
	$(CC) $(CFLAGS) $(LIBS) $(SRC) -o $@

debug: CFLAGS += -g
debug: all
