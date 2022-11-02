/*
BSD 2-Clause License

Copyright (c) 2022, danristea
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

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
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
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
