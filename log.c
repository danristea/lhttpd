#include <errno.h>
#include <stdarg.h>
#include <syslog.h>
#include <unistd.h>
#include <stdlib.h>

#include "httpd.h"

static int debug;
static int foreground = 1;

void
log_init(char *progname, int dbg, int fg)
{
    debug = dbg;
    foreground = fg;

    if (!foreground) {
        openlog(progname, LOG_PID|LOG_NDELAY, LOG_DAEMON);
        //close(STDERR_FILENO);
    }
}

static void
log_write(int priority, const char *fmt, va_list ap)
{
    //if (foreground || isatty(STDERR_FILENO)) {
    if (foreground) {
        vfprintf(stderr, fmt, ap);
        fprintf(stderr, "\n");
        //vfprintf_s(stderr, fmt, ap);
        fflush(stderr);
        //setbuf(stderr, NULL);
    } else
        vsyslog(priority, fmt, ap);
}

void
log_ex(struct server *srv, int priority, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    log_write(priority, fmt, ap);
    va_end(ap);
    if (srv) {
        //cleanup();
        exit(1);
    }
}

void
log_dbg(int priority, const char *fmt, ...)
{
    va_list	 ap;
    int savederrno;

    if ((!debug) || (priority > debug))
        return;

    savederrno = errno;
    va_start(ap, fmt);
    log_write(priority, fmt, ap);
    va_end(ap);
    errno = savederrno;
}
