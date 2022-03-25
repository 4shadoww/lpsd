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

install: $(EXECUTABLE)
	install $(EXECUTABLE) /usr/bin/
	gzip man/lpsd.1 -c > man/lpsd.1.gz
	install -m 644 man/lpsd.1.gz /usr/share/man/man1/lpsd.1.gz

uninstall:
	rm /usr/bin/$(EXECUTABLE)
	rm /usr/share/man/man1/lpsd.1.gz
