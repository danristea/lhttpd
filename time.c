/*
BSD 2-Clause License

Copyright (c) 2022, Daniel Ristea <daniel.ristea@outlook.com>
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

#define _DEFAULT_SOURCE

#ifdef __linux__
#define _XOPEN_SOURCE 700
#endif

#include <time.h>
#include <sys/time.h>
#include <stdio.h>

#ifdef __MACH__
#include <mach/clock.h>
#include <mach/mach.h>
#endif

long
ts_to_tv(struct timespec *ts)
{
    return (long)ts->tv_sec * 1000000000L + ts->tv_nsec;
}

struct timespec
tv_to_ts(unsigned long tv)
{
    return (struct timespec) {.tv_sec = tv / 1000, .tv_nsec = (tv % 1000) * 1000000};
}

// Use clock_gettime in linux, clock_get_time in OS X.
// courtesy of https://stackoverflow.com/questions/5167269/clock-gettime-alternative-in-mac-os-x
void
get_monotonic_time(struct timespec *ts)
{
#ifdef __MACH__
    clock_serv_t cclock;
    mach_timespec_t mts;
    host_get_clock_service(mach_host_self(), SYSTEM_CLOCK, &cclock);
    clock_get_time(cclock, &mts);
    mach_port_deallocate(mach_task_self(), cclock);
    ts->tv_sec = mts.tv_sec;
    ts->tv_nsec = mts.tv_nsec;
#else
    clock_gettime(CLOCK_MONOTONIC, ts);
#endif
}

char *
httpd_time(char *date, size_t datelen)
{
    time_t now = time(NULL);
    struct tm *tm = gmtime(&now);
    strftime(date, datelen, "%a, %d %h %Y %T %Z", tm);
    return date;
}

int
parse_date(const char *val, time_t *timestamp)
{
    struct tm tm;

    if (strptime(val, "%a, %d %h %Y %T %Z", &tm) && (*timestamp = timegm(&tm)))
        return 1;

    return 0;
}

// Use clock_gettime in linux, clock_get_time in OS X.
// courtesy of https://stackoverflow.com/questions/5167269/clock-gettime-alternative-in-mac-os-x
void
get_calendar_time(struct timespec *ts)
{
#ifdef __MACH__
    clock_serv_t cclock;
    mach_timespec_t mts;
    host_get_clock_service(mach_host_self(), CALENDAR_CLOCK, &cclock);
    clock_get_time(cclock, &mts);
    mach_port_deallocate(mach_task_self(), cclock);
    ts->tv_sec = mts.tv_sec;
    ts->tv_nsec = mts.tv_nsec;
#else
    clock_gettime(CLOCK_REALTIME, ts);
#endif
}

double
get_elapsed_time(struct timespec *before, struct timespec *after)
{
    double deltat_s  = after->tv_sec - before->tv_sec;
    double deltat_ns = after->tv_nsec - before->tv_nsec;
    return deltat_s + deltat_ns*1e-9;
}
