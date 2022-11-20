EXECUTABLE=lpsd
BUILDDIR=
OBJDIR=obj

CC=gcc
SRC=lpsd.c
IDIR=
LIBS=

CFLAGS=-Wall -std=gnu17 -O2 -pthread

all: lpsd

$(EXECUTABLE): $(SRC)
	$(CC) $(CFLAGS) $(LIBS) $(SRC) -o $@

profile: CFLAGS += -pg
profile: all
debug: CFLAGS += -g
debug: all

install: $(EXECUTABLE)
	install -D $(EXECUTABLE) ${DESTDIR}/usr/bin/
	gzip man/lpsd.1 -c > man/lpsd.1.gz
	install -D -m 644 man/lpsd.1.gz ${DESTDIR}/usr/share/man/man1/lpsd.1.gz

uninstall:
	rm ${DESTDIR}/usr/bin/$(EXECUTABLE)
	rm ${DESTDIR}/usr/share/man/man1/lpsd.1.gz
