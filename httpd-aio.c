//#include <stdlib.h>

#include "httpd-aio.h"

/* linux */
#ifdef  __linux__

#define _GNU_SOURCE

#include <linux/aio_abi.h>
#include <sys/syscall.h>
#include <sys/eventfd.h>

inline int io_setup(unsigned nr, aio_context_t *ctxp) {
	  return syscall(__NR_io_setup, nr, ctxp);
}

inline int io_destroy(aio_context_t ctx) {
	  return syscall(__NR_io_destroy, ctx);
}

inline int io_submit(aio_context_t ctx, long nr, struct iocb **iocbpp) {
	  return syscall(__NR_io_submit, ctx, nr, iocbpp);
}

inline int io_getevents(aio_context_t ctx, long min_nr, long max_nr, struct io_event *events, struct timespec *timeout) {
	  return syscall(__NR_io_getevents, ctx, min_nr, max_nr, events, timeout);
}


struct async_io *
aio_init(int pipe[2])
{
	  struct async_io *aio;
		aio_context_t aioc = 0;
		int rv;

		// no need for the pipe here - linux has eventfd - so close the pipe here
		//for (int i = 0; i < sizeof(*pipe); i++) {
		//    if (fd_is_valid(pipe[i]))
		//		    close(pipe[i]);
	  //}

    pipe[0] = pipe[1] = eventfd(0, EFD_NONBLOCK|EFD_CLOEXEC);

	  aio = (struct async_io *) calloc(1, sizeof(struct async_io));
	  assert(aio);

	  aio->alist = (struct iocb*) calloc(MAX_AIO, sizeof(struct iocb));
	  aio->nlist = (struct iocb*) calloc(MAX_AIO, sizeof(struct iocb));

		aio->sigd = &pipe[1];

		rv = io_setup(MAX_AIO, &aioc);
		assert(rv == 0);

		aio->aid = aioc;

		return aio;
}

void
schedule_aio_read(struct async_io *aio, struct aio_data *aio_d)
{
		struct iocb *acb = (struct iocb *) aio->nlist;
		struct iocb *abr = (struct iocb *) aio->alist;
		int rv;
		char *buf;

    memset(&acb[aio->nc], 0, sizeof(struct iocb));

		acb[aio->nc].aio_buf = (u_int64_t) aio_d->buf;
		acb[aio->nc].aio_nbytes = aio_d->len;
		acb[aio->nc].aio_offset = aio_d->pos;
		acb[aio->nc].aio_fildes = aio_d->fd;
		acb[aio->nc].aio_resfd = *(int*) aio->sigd;
		acb[aio->nc].aio_lio_opcode = IOCB_CMD_PREAD;
		acb[aio->nc].aio_flags = IOCB_FLAG_RESFD;
		acb[aio->nc].aio_data = (u_int64_t) aio_d;

    aio->nc += 1;
}

void
schedule_aio_write(struct async_io *aio, struct aio_data *aio_d)
{
    //struct aiocb *acb = (struct aiocb *) aio_cb;
		struct iocb *acb = (struct iocb *) aio->nlist;
		struct iocb *abr = (struct iocb *) aio->alist;
		int rv;

//    memset(&acb[aio->nc], 0, sizeof(struct aiocb));

   acb[aio->nc].aio_buf = (u_int64_t) aio_d->buf;
   acb[aio->nc].aio_nbytes = aio_d->len;
   acb[aio->nc].aio_offset = aio_d->pos;
   acb[aio->nc].aio_fildes = aio_d->fd;
   acb[aio->nc].aio_resfd = *(int*) aio->sigd;
   acb[aio->nc].aio_lio_opcode = IOCB_CMD_PWRITE;
   acb[aio->nc].aio_flags = IOCB_FLAG_RESFD;
   acb[aio->nc].aio_data = (u_int64_t) aio_d;
   //acb[aio->nc].aio_sigevent.sigev_value.sival_ptr = aio_d;

    aio->nc += 1;
}

void
lh_aio_schedule(struct async_io *aio, void *ctx)
{
   struct iocb* test[MAX_AIO];
	 struct iocb* alist;

	 memcpy(aio->alist, aio->nlist, sizeof(struct iocb) * MAX_AIO);

	 alist = (struct iocb*) aio->alist;

	 for (int i = 0; i < aio->nc; i++)
	    test[i] = &alist[i];

		struct iocb *acb_l = (struct iocb *)aio->alist;

		aio->ac = aio->nc;

		int rv;

		rv = io_submit(aio->aid, aio->ac, test);

		if (rv < 0) {
			  errno = 0;
			  fprintf(stderr, "\nBAD AIO RETURN");
		}

		assert(rv >= 0);

		aio->nc = 0;
		aio->wait = 1;
}

int
lh_aio_reap(struct async_io *aio, struct aio_data *aio_d[], int ac)
{
		struct iocb *acb;
		struct io_event io_e[MAX_AIO];
		struct timespec ts;
		struct strm;
		int r;

		ts.tv_sec = 0;
		ts.tv_nsec = 0;

    r = io_getevents(aio->aid, 0, MAX_AIO, io_e, &ts);

		for (int i = 0 ; i < r; i++) {
			  aio_d[i] = (struct aio_data*) io_e[i].data;

				struct iocb* icb = (struct iocb*) io_e[i].obj;
				fprintf(stderr, "\n-------------------------------------------------------------\n");
				fprintf(stderr, "\n= %s", icb->aio_buf);
				fprintf(stderr, "\n= %i", icb->aio_nbytes);

				aio_d[i]->pos += aio_d[i]->len;
				aio_d[i]->ready = 1;
		}
		return ac;
}

#else
// #elif _freebsd_ __MACH__
#include <aio.h>
#include <sys/uio.h>


struct async_io *
aio_init(int pipe[2]) {
    struct async_io *aio;

    aio = (struct async_io *) calloc(1, sizeof(struct async_io));
    assert(aio);

		aio->alist = (struct aiocb*) calloc(MAX_AIO, sizeof(struct aiocb));
    aio->nlist = (struct aiocb*) calloc(MAX_AIO, sizeof(struct aiocb));

		memset(aio->alist, 0, sizeof(struct aiocb) * 16);
	 	memset(aio->nlist, 0, sizeof(struct aiocb) * 16);

    aio->ac = 0;

    return aio;
}

void
schedule_aio_read(struct async_io *aio, struct aio_data *aio_d)
{
    //struct aiocb *acb = (struct aiocb *) aio_cb;
		struct aiocb *acb = (struct aiocb *) aio->nlist;
		struct aiocb *abr = (struct aiocb *) aio->alist;
		int rv;

//    memset(&acb[aio->nc], 0, sizeof(struct aiocb));

    acb[aio->nc].aio_buf = aio_d->buf;
    acb[aio->nc].aio_nbytes = aio_d->len;
    acb[aio->nc].aio_offset = aio_d->pos;
    acb[aio->nc].aio_fildes = aio_d->fd;
    acb[aio->nc].aio_lio_opcode = LIO_READ;
    acb[aio->nc].aio_sigevent.sigev_value.sival_ptr = aio_d;

    aio->nc += 1;
}


void
schedule_aio_write(struct async_io *aio, struct aio_data *aio_d)
{
	  struct aiocb *acb = (struct aiocb *) aio->nlist;
	  struct aiocb *abr = (struct aiocb *) aio->alist;
	  int rv;

//    memset(&acb[aio->nc], 0, sizeof(struct aiocb));

    acb[aio->nc].aio_buf = aio_d->buf;
    acb[aio->nc].aio_nbytes = aio_d->len;
    acb[aio->nc].aio_offset = aio_d->pos;
    acb[aio->nc].aio_fildes = aio_d->fd;
    acb[aio->nc].aio_lio_opcode = LIO_WRITE;
    acb[aio->nc].aio_sigevent.sigev_value.sival_ptr = aio_d;

	  aio->nc += 1;
}

void
lh_aio_schedule(struct async_io *aio, void *ctx)
{
   struct aiocb* test[MAX_AIO];
	 struct aiocb* alist;

	 memcpy(aio->alist, aio->nlist, sizeof(struct aiocb) * MAX_AIO);

	 alist = (struct aiocb*) aio->alist;

	 for (int i = 0; i < aio->nc; i++)
	    test[i] = &alist[i];


		struct aiocb *acb_l = (struct aiocb *)aio->alist;

		aio->ac = aio->nc;

    struct sigevent se;
		int rv;

		memset(&se, 0, sizeof(struct sigevent));

		se.sigev_notify = SIGEV_SIGNAL;
		se.sigev_signo = SIGIO;
		se.sigev_value.sival_ptr = ctx;

		rv = lio_listio(LIO_NOWAIT, test, aio->ac, &se);

		if (rv < 0) {
			  errno = 0;
			  for (int i = 0; i < aio->ac; i++)  {
					int x = aio_error(&acb_l[i]);
				  fprintf(stderr, "\nrv: %i, error: %s\n", x, (x > 0)? strerror(x): "-");
				}
		}

		assert(rv == 0);

		aio->nc = 0;
		aio->wait = 1;
}

int
lh_aio_reap(struct async_io *aio, struct aio_data *aio_d[], int ac)
{

		struct aiocb *acb = (struct aiocb *) aio->alist;
		struct strm;
		int rv;

		for (int i = 0; i < ac; i++) {
				if (aio_error(&acb[i]) == 0) {
						rv = aio_return(&acb[i]);

						aio_d[i] = acb[i].aio_sigevent.sigev_value.sival_ptr;
						aio_d[i]->len = rv;
						aio_d[i]->pos += rv;
//						aio_d[i]->ready = 1;

						if (aio_d[i]->pos >= aio_d[i]->flen)
						    aio_d[i]->ready = 1;
						//	  LIST_REMOVE(aio_d[i], next);
						//}
				}
		}

		return ac;
}

#endif
