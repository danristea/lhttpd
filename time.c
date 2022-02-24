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

// Use clock_gettime in linux, clock_get_time in OS X.
void get_monotonic_time(struct timespec *ts){
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
    struct tm tm = *gmtime(&now);
    strftime(date, datelen, "%a, %d %h %Y %T %Z", &tm);
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
void get_calendar_time(struct timespec *ts){
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

double get_elapsed_time(struct timespec *before, struct timespec *after){
    double deltat_s  = after->tv_sec - before->tv_sec;
    double deltat_ns = after->tv_nsec - before->tv_nsec;
    return deltat_s + deltat_ns*1e-9;
}
