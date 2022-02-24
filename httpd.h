#ifndef _HTTPD_H_
#define _HTTPD_H_ 1

#ifndef SOFTWARE_NAME
#define SOFTWARE_NAME	"lhttpd"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <stddef.h>

#include <sys/socket.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>

//#include "queue.h"
#include "lua.h"
#include "event.h"
#include "httpd-aio.h"
#include "http.h"


//#include "lualib.h"
#include "lauxlib.h"
#include "bearssl.h"
#include "brssl.h"
#include <hpack.h>


//#include "hpack.h"

#define BUFFER_SIZE 4096
#define H2_HEADER_SIZE 9
#define H2_SETTINGS_FIELDS 6
#define H2_MAX_HEADER_FIELDS 64

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

enum conn_state {
    CS_INIT = (0x0),
    CS_RECV = (0x1),
    CS_SEND = (0x2),
    CS_WAIT = (0x4),
    CS_CLOSE = (0x8),
    CS_ERROR = (0x10)
};

struct http_hfield {
   const char* name;
   const char* value;
};

//enum strm_state {
//    SS_INIT, SS_RECV, SS_HEAD, SS_SEND, SS_WAIT, SS_ERROR
//};

enum strm_state {
    SS_INIT = (0x0),
    SS_WAIT = (0x1),
    SS_RECV = (0x2),
    SS_HEAD = (0x4),
    SS_SEND = (0x8),
    SS_CLOSE = (0x10),
    SS_ERROR = (0x100)
};

// BR_SSL_CLOSED    0x0001
// BR_SSL_SENDREC   0x0002
// BR_SSL_RECVREC   0x0004
// BR_SSL_SENDAPP   0x0008
// BR_SSL_RECVAPP   0x0010

typedef union {
    struct sockaddr		sa;
    struct sockaddr_in	sa4;
    struct sockaddr_in6	sa6;
} sock_addr;

typedef struct lua_map {
    const char 	*script;
    const char	*prefix;
    SIMPLEQ_ENTRY(lua_map) next;
} lua_map;

typedef struct config {
    char *port;
    double timeout;
    char *addr;
    char *user;
    char *rootdir;
    char *lua_prefix;
    char *lua_script;
    void *tls_config;
    char *cert_file;
    char *pkey_file;
    char *mime;
    int debug;
    int fg;
    SIMPLEQ_HEAD(l_map, lua_map) l_map;
} config;

struct h2_settings {
	  uint32_t header_table_size;
	  uint32_t enable_push;
	  uint32_t max_concurrent_streams;
	  uint32_t window_size;
	  uint32_t max_frame_size;
	  uint32_t max_header_list_size;
};

/*
struct h2_frame {
	  uint8_t	f_len[3];
	  uint8_t	f_typ;
	  uint8_t	f_flg;
	  uint8_t	f_sid[4];
};
*/


struct h2_frame {
	  uint32_t f_len; //size_t f_len;
	  uint8_t f_typ;
	  uint8_t f_flg;
	  uint32_t f_sid;
};

struct hp {
    char* data;
    size_t offset;
};

struct frame_header {
    uint8_t data[H2_HEADER_SIZE];
};

struct frame_settings {
    struct frame_header fh;
    struct {
        uint16_t id;
        uint32_t val;
    } fields[];
};


typedef struct lua_handler {
	  const char	*name;
	  int		 ref;
	  SIMPLEQ_ENTRY(lua_handler) next;
} lua_handler;

typedef struct lua_state_map {
    const char 	*script;
    const char	*prefix;
    lua_State	*L;
    SIMPLEQ_HEAD(l_hand, lua_handler) l_hand;
    SIMPLEQ_ENTRY(lua_state_map) next;
} lua_state_map;

/*
struct cb_data {
    short typ;
    union {
        struct edata e_dat;
        struct adata a_dat;
    } dt;
};
*/

/*
typedef struct strm_file {
    FILE* F;
    off_t len;
    off_t idx;
    char* buf;
    SIMPLEQ_ENTRY(strm_file) next;
} strm_file;
*/

struct stream {
    //struct aio_data aio_d;
    LIST_HEAD(aio_d, aio_data) aio_d;
    struct edata ev;
    enum strm_state ss;

    lua_State* L; //take it out maybe
    lua_State* T;
    struct connect* conn;

    int id;
    int pri;
    int fd;
    //FILE** f;
    luaL_Buffer lb;
    int lua_status;

    //unsigned char* buf;
    //int lwm;
    //int io_hwm;
    //int io_lwm;
    size_t io_len;
    size_t io_idx;
    size_t io_pos; //new
    char *io_buf;
    int rb;
    int rd;
    int fsio;
    int not_found;

    //HTTP/2
    enum h2_stream_state h2_ss;
    enum h2_error_codes h2_err;
    uint32_t h2_sid;
    int h2_dep;
    int h2_wgt;
    int h2_flg;
    int window_size;

    char *method;     //:method (HTTP/2)
    char *scheme;     //:scheme (HTTP/2)
    char *authority;  //:authority (HTTP/2)
    char *path;       //:path (HTTP/2)

    enum http_method http_method;
    char* content;
    char* content_type;
    char* host;
    char* referrer;
    char* range;
    char* modified_since;
    char* accept_encoding;
    char* user_agent;
    char* accept;
    long content_len;
    long tlen;
    int http_status;

    struct header* head;

    struct stream* next;
    struct stream* prev;
    int sh;
//    SIMPLEQ_HEAD(s_file, strm_file) s_file;
};

struct thread {
    struct equeue *eq;
    pthread_t tid;
    int pfd[2];
    struct async_io *aio;
    struct edata ev[2];
    //struct equeue *eq;
    struct server *srv;
    struct connect *conn;
    struct connect *conn_head;
    struct connect *conn_tail;
    char cb;
    SIMPLEQ_HEAD(L_map, lua_state_map) L_map;
};

struct server {
    struct edata ev;
    int fd;
    int ti;
    uintptr_t aid; // fd or signal for aio signaling
//    struct sigevent se;
    sock_addr sa46;
    char *progname;
    char *pidfile;
    struct config *conf;
    long timeout;
    struct thread *thr;
    size_t cert_len;
    br_x509_certificate *cert;
    private_key *pkey;
};

struct connect {

    struct edata ev;

    enum conn_state cs;

    int fd;
    struct sockaddr_storage ss;

    long timestamp;
    struct thread* thr;

    struct connect* next_actv;
    struct connect* prev_actv;

    struct stream *strm;
    struct stream *strm_head;
    struct stream *strm_tail; //tail might not be needed

    enum http_protocol http_protocol;
    char* protocol;

    int keep_alive;
    int conn_close;
    int upgrade;

    int mime_flag;
    int http_11; // might not be neeeded

    char* buf;
    char rbuf[BUFFER_SIZE * 10];
    size_t rlen;

    // ssl
    br_ssl_server_context ssl_sc;
    br_sslio_context ssl_ioc;
    unsigned ssl_state; //might not be necessary depending on implementation

    // HTTP/2
    struct h2_frame h2_frm;
    struct hpack *encoder;
    struct hpack *decoder;
    uint8_t *hb;

    enum h2_state h2_state;
    enum h2_error_codes h2_err;
    struct h2_settings h2_set;

    int cont_sid;
    int prom_sid;
    int f_len;
    int send_settings;
    int send_ping;
    char* ping_data;

    int h2_preface;
    int hs;

    int cdbg;
};




//log.c
void log_init(char *progname, int dbg, int fg);
void log_ex(struct server *srv, int priority, const char *fmt, ...);
void log_dbg(int priority, const char *fmt, ...);

//time.c
void get_monotonic_time(struct timespec *ts);
void get_calendar_time(struct timespec *ts);
char* httpd_time(char *date, size_t datelen);
double get_elapsed_time(struct timespec *before, struct timespec *after);

//httpd-lua.c
int lua_map_create(struct thread*, struct l_map*);
//int lua_create_smap lua_create_states
int process_lua(struct stream*);
static int register_handler(lua_State*);
struct lua_handler* find_handler(struct lua_state_map*, char*);
void stack_dump(lua_State *L, const char *stackname);
int lev_read(struct stream* strm, char* buf, int len);
int lev_write(struct stream* strm, char* buf, int len);
void lthread_remove(lua_State *, lua_State **);
int lua_run(lua_State *, lua_State *, int);
void lh_aio_dispatch(struct aio_data *aio_d);


// httpd-aio
//void lh_aio_ready(uintptr_t aid, struct thread *thr);
//void lh_aio_ready(uintptr_t aid, void *thr);
//void lh_aio_ready(int fd, void *thr);
void thread_wakeup(struct edata *ev);

//httpd.c
char* e_strdup(const char* oldstr);
void* serve(void *thread);

int new_conn(struct thread* thr);
void del_conn(struct connect* conn);

void conntab_create(struct edata *ev);
void conntab_remove(struct connect*);
void conntab_update(struct connect*);

void conn_read(struct edata *ev);
void conn_write(struct edata *ev);

void http_write_header(struct connect* conn);
void http_write_body(struct connect* conn);

void https_io(void* edata);
void conn_resume(struct stream*);
void rw_io(void* edata);
void reset_headers(struct stream*);

//int http2_write(struct connect*, char*, int);
int http2_read(struct connect*, char*, int);

struct stream* new_strm(struct connect* conn, uint32_t sid);

//event.c
//int equeue_init(struct equeue**);
//int equeue_add(struct equeue*, int, void*);
//int equeue_add(struct equeue*, int, short, void*);
//int equeue_poll(struct equeue *eq, int tv);

//static double ts_to_tv(struct timespec* ts);
static long ts_to_tv(struct timespec* ts);
struct timespec tv_to_ts(unsigned long tv);

#endif
/*

struct connect {
    int sfd;
    struct sockaddr_in6 sa;
    enum {FREE, RECV, SEND} status;
    double timestamp;
    header *request;
    header *response;
};


void fd_send(struct connect*);
void fd_recv(struct connect*);
double ts_to_tv(struct timespec* ts);
struct timespec* tv_to_ts(double tv);

*/
/* event.c */
/*
int equeue_init(void);
void equeue_edit(int id, void *conn);
void equeue_exec(int id, double tval);
*/
