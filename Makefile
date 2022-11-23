CC= cc
OPT= -O

LDIR =/usr/local/lib
IDIR =/usr/local/include

FILES= main.c server.c httpd.c log.c event.c time.c httpd-lua.c httpd-aio.c hpack.c
SSLFILES= bearssl/tools/files.c bearssl/tools/vector.c bearssl/tools/names.c bearssl/tools/xmem.c bearssl/tools/keys.c bearssl/tools/errors.c
LIBS= -I$(IDIR) -L$(LDIR) -lpthread -ldl -lbearssl -lluajit -lm

linux:
		$(CC) $(OPT) -o lhttpd $(FILES) $(SSLFILES) $(LIBS) -laio -D HAVE_SYS_EPOLL_H
bsd:
		$(CC) $(OPT) -o lhttpd $(FILES) $(SSLFILES) $(LIBS) -D HAVE_SYS_EVENT_H
macos:
		$(CC) $(OPT) -o lhttpd $(FILES) $(SSLFILES) $(LIBS) -D HAVE_SYS_EVENT_H -pagezero_size 10000
clean:
		rm -f lhttpd *.o
