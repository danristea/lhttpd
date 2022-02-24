#include <fcntl.h>
#include <ctype.h>
#include <dirent.h>
#include <sys/stat.h>

#include "httpd.h"


#if !(SERVER_RSA || SERVER_EC || SERVER_MIXED)
#define SERVER_RSA     1
#define SERVER_EC      0
#define SERVER_MIXED   0
#endif

#define INIT_HB_BUF_SIZE (1 << 13)

static const char* http_methods[] = HTTP_METHODS;
static const char* http_protocols[] = HTTP_PROTOCOLS;
const char *proto_name = "h2";

// default http/2 settings
struct h2_settings h2_settings = {
	  .header_table_size = 4096,
	  .enable_push = 1,
	  .max_concurrent_streams = 1,
	  .window_size = 65535,
	  .max_frame_size = 16384,
	  .max_header_list_size = 0xFFFFFFFF
};

void lhttpd_noop() {(void)0;};


int http_response(struct stream* strm, int code, char* desc, struct header* header, int blen, char* buf, int len);
static void strdecode(char* str);

int http2_write(struct connect* conn, char** buf, int len);

void conn_io(struct connect* conn);
void conn_read(struct edata *ev);
void conn_write(struct edata *ev);

void app_send(struct connect* conn);
void app_recv(struct connect* conn);



// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
	  if (sa->sa_family == AF_INET) {
		    return &(((struct sockaddr_in*)sa)->sin_addr);
	  }

	  return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

// initialize http/2 specifics: hpack, settings, states
int
h2_init(struct connect* conn)
{
    if ((conn->encoder = hpack_encoder(h2_settings.header_table_size, -1, hpack_default_alloc)) == NULL)
		    goto err;
    if ((conn->decoder = hpack_decoder(h2_settings.header_table_size, -1, hpack_default_alloc)) == NULL)
		    goto err;

	  if ((conn->hb = malloc(INIT_HB_BUF_SIZE)) == NULL)
		    goto err;

		conn->protocol = TXT_HTTP2;
    conn->http_protocol = HTTP2;
		conn->h2_state = H2_WAITING_MAGIC;
		conn->h2_set = h2_settings;
		conn->h2_preface = 1;

		conn->cs |= CS_SEND;

    return 0;

err:
		log_dbg(5, "h2_init failed");
		conn->cs = CS_ERROR;
    return -1;
}

void
change_state(struct connect* conn, enum strm_state st)
{
		if (conn->http_protocol < HTTP2) {
			  if (st & SS_WAIT) {
						conn->cs = CS_WAIT;
					  return;
				}
//				if (st == SS_CLOSE) {
//					  conn->cs = CS_CLOSE;
//					  return;
//				}
			  if (st == SS_ERROR) {
					conn->cs = CS_CLOSE;
					return;
				}

				if (st == SS_INIT) {
						if (conn->conn_close == 1)
								conn->cs = CS_CLOSE;
						else
								conn->cs = CS_RECV;
					  return;
				}

				if (st == SS_SEND) {
				    conn->cs = CS_SEND;
						return;
				}
				if (st == SS_RECV) {
					  conn->cs = CS_RECV;
						return;
				}
				if (st == SS_HEAD) {
						conn->cs = CS_SEND;
						return;
				}
		} else {
			  if (conn->cs & CS_WAIT)
				    conn->cs ^= CS_WAIT;
		}

}

void
http2_error (struct connect* conn, int err) {
	  log_dbg(5, "ERROR: %i", err);

	  return;
}

void
strm_reset(struct stream* strm)
{
	  struct connect* conn = strm->conn;

log_dbg(5, "\n#####\nSTRM RESET\n#####\n");

for (struct stream* sp = conn->strm_head; sp != NULL; sp = sp->next)
    log_dbg(5, "B-> strm->h2_sid: %i", sp->h2_sid);

	  strm->http_method = 0;
		strm->L = NULL; // take it out maybe
		strm->T = NULL;
		strm->rd = 0;
		strm->ss = SS_INIT;
		strm->h2_err = 0;
		strm->h2_ss = 0;

//		strm->io_st = IO_RECV;
    strm->ss = 0;
		strm->lua_status = 0;
		strm->not_found = 0;

		strm->io_len = 0;
		strm->io_idx = 0;
		strm->io_pos = 0; //new
		strm->io_buf = NULL;
		strm->fsio = 0;

		strm->fd = -1;

//		if (strm->conn->http_protocol != HTTP2) {
//			  struct connect* conn = strm->conn;

//				if ((conn->keep_alive) && (strm->not_found == 0)) {
//				    conn->cs -= CS_SEND;
//				    conn->cs += CS_RECV;
//				} else
//				    conn->cs = CS_CLOSE;
//		}
log_dbg(5, "here0");

//for (struct aio_data* ad = conn->thr->nlist)

//memset(&strm->aio_d, 0, sizeof(struct aio_data));
//SIMPLEQ_FOREACH(Lm, &conn->thr->L_map, next)
struct aio_data *aio_d;
struct aio_data *ad;
LIST_FOREACH_SAFE(aio_d, &strm->aio_d, next, ad) {
	   free(aio_d);

}
LIST_EMPTY(&strm->aio_d);



if (conn->strm_head == strm) {
		conn->strm_head = strm->next;
		for (struct stream* sp = conn->strm_head; sp != NULL; sp = sp->next)
				log_dbg(5, "BI-> strm->h2_sid: %i", sp->h2_sid);
} else if (strm->prev) {

		strm->prev->next = strm->next;
		for (struct stream* sp = conn->strm_head; sp != NULL; sp = sp->next)
				log_dbg(5, "BI1-> strm->h2_sid: %i", sp->h2_sid);
}
log_dbg(5, "here");

for (struct stream* sp = conn->strm_head; sp != NULL; sp = sp->next)
		log_dbg(5, "I-> strm->h2_sid: %i", sp->h2_sid);

if (conn->strm_tail == strm)
		conn->strm_tail = strm->prev;
else if (strm->next)
    strm->next->prev = strm->prev;

	  strm->next = NULL;
	  strm->prev = NULL;

		for (struct stream* sp = conn->strm_head; sp != NULL; sp = sp->next)
		    log_dbg(5, "A-> strm->h2_sid: %i", sp->h2_sid);
}

struct stream*
h2_find_stream(struct connect* conn, uint32_t h2_sid)
{
		struct stream *strm;

	  for (strm = conn->strm_head; strm != NULL; strm = strm->next) {
			  if (h2_sid == strm->h2_sid)
				    return strm;
		}
		return NULL;
}

void
construct_frame_header(uint8_t *buf, uint32_t length, uint8_t flags, uint8_t type, uint32_t stream_id)
{
	  buf[2] = length & 0xFF;
	  buf[1] = (length >> 8) & 0xFF;
	  buf[0] = (length >> 16) & 0xFF;
	  buf[3] = type;
	  buf[4] = flags;
	  buf[8] = stream_id & 0xFF;
	  buf[7] = (stream_id >> 8) & 0xFF;
	  buf[6] = (stream_id >> 16) & 0xFF;
	  buf[5] = (stream_id >> 24) & 0x7F;
}


char*
strnstr(const char *s, const char *find, size_t slen)
{
	char c, sc;
	size_t len;

	if ((c = *find++) != '\0') {
		len = strlen(find);
		do {
			do {
				if (slen-- < 1 || (sc = *s++) == '\0')
					return (NULL);
			} while (sc != c);
			if (len > slen)
				return (NULL);
		} while (strncmp(s, find, len) != 0);
		s--;
	}
	return ((char *)s);
}

void
reset_headers(struct stream* strm)
{
    struct header* ph = strm->head;

    for (struct header* head = ph; head;) {
        ph = head->next;
        head->next = NULL;
        free(head);
        head = ph;
    }
    free(ph);
    strm->head = NULL;
    free(strm->path);
    strm->path = NULL;
    //strm->io_lwm = 0;
    //strm->io_hwm = 0;

    if (strm->h2_ss != SS_CLOSED) {
        //strm->io_buf = realloc(strm->io_buf, BUFFER_SIZE);
        //strm->io_len = BUFFER_SIZE;
    }
    strm->method = NULL;

    if (strm->path != NULL) {
        free(strm->path);
        strm->path = NULL;
    }

    //close(strm->fd);
    //strm->fd = -1;

    strm->content_len = 0;
    strm->http_method = 0;
//    strm->io_len = 0;
//    strm->io_idx = 0;
		strm->rd = 0;
		strm->ss = 0;
}

const char*
assign_mime(char* path)
{
     struct content_type* ct;
     char* mime;

     if ((mime = strchr(path, '.')) == NULL)
         mime = path;

     for (ct = content_type; ct->ext; ct++)
         if (strcasecmp(mime, ct->ext) == 0)
             break;
     return ct->type;
}

int
start_lua(struct stream* strm, char* path)
{
		struct connect* conn = strm->conn;
		struct lua_state_map* Lm;
		struct lua_handler* lh;
		lua_State *T;
		char addr[INET6_ADDRSTRLEN];
		char date[32];
		char* handler;
		char* query;
		int len;

		// get the query from path
		if ((query = strchr(path, '?')) != NULL) {
				*query++ = '\0';
		}

		// loop through lua map states
		SIMPLEQ_FOREACH(Lm, &conn->thr->L_map, next) {

		    len = strlen(Lm->prefix) + 1;
				// check if lua map state is found
			  if (strstr(&path[1], Lm->prefix) != &path[1] || path[len] != '/')
				    continue;

			  // extract handler value from path
				handler = &path[len];
				while (handler[0] == '/')
						handler++;

				// try to find handler
				lh = find_handler(Lm, handler);

				// if handler not found, see if we have a notfound fallback
				if (lh == NULL) {
						lh = find_handler(Lm, "notfound");

						if (lh == NULL)
						    return 0;
				}

				strm->L = Lm->L;
				T = lua_newthread(Lm->L);

				if (T == NULL) {
						log_dbg(5, "PROCESS_LUA: cannot create lua thread");
						return -1;
				}

				lua_rawgeti(Lm->L, LUA_REGISTRYINDEX, lh->ref);
				lua_xmove(Lm->L, T, 1);

				lua_pushlightuserdata(T, T);
				lua_pushlightuserdata(T, strm);
				lua_settable(T, LUA_REGISTRYINDEX);

				lua_newtable(T);
				lua_pushstring(T, SOFTWARE_NAME);
				lua_setfield(T, -2, "SERVER_SOFTWARE");
				lua_pushstring(T, conn->protocol);
				lua_setfield(T, -2, "SERVER_PROTOCOL");
				lua_pushstring(T, conn->thr->srv->conf->lua_script);
				lua_setfield(T, -2, "SCRIPT_FILENAME");
				lua_pushstring(T, conn->thr->srv->conf->lua_prefix);
				lua_setfield(T, -2, "SCRIPT_PREFIX");
				lua_pushstring(T, lh->name);
				lua_setfield(T, -2, "HANDLER_NAME");
				//lua_pushstring(T, inet_ntop(AF_INET6, &conn->thr->srv->sa.sin6_addr, addr, INET6_ADDRSTRLEN));

	//			inet_ntop(AF_INET4, &conn->thr->srv->sa.sin6_addr, addr, INET_ADDRSTRLEN);
//				inet_ntop(conn->ss.ss_family, get_in_addr((struct sockaddr *)&conn->thr->srv->ss), addr, INET_ADDRSTRLEN);

//				lua_pushstring(strm->T, addr);

//				lua_setfield(T, -2, "SERVER_ADDR");
//				lua_pushinteger(T, ntohs(conn->thr->srv->sa.sin6_port));
//				lua_setfield(T, -2, "SERVER_PORT");
//				lua_pushinteger(T, ntohs(conn->sa.sin6_port));
//				lua_setfield(T, -2, "CLIENT_PORT");
//				lua_pushstring(T, inet_ntop(AF_INET6, &conn->sa.sin6_addr, addr, INET6_ADDRSTRLEN));
	//			lua_setfield(T, -2, "CLIENT_ADDR");
				lua_pushstring(T, query);
				lua_setfield(T, -2, "QUERY_INFO");
				lua_pushstring(T, httpd_time(date, sizeof date));
				lua_setfield(T, -2, "DATE_UTC");

				// headers
				lua_newtable(T);

				strm->T = T;
		}
		return 0;
} //f

// add new header field to hpack struct and increase field count
void
add_header(struct hpack_field *hp_fld, char const* key, char const* val, int* fc)
{
		int i = *fc;

		// add to the structure
	  hp_fld[i].nam = key;
	  hp_fld[i].val = val;
		hp_fld[i].flg = HPACK_FLG_TYP_LIT | HPACK_FLG_NAM_HUF | HPACK_FLG_VAL_HUF;

		// increment number of header fields
	  (*fc)++;
}

// encoder callback function that adds data to buffer and advances offset
static void
encode_header(enum hpack_event_e e, const char *buf, size_t len, void *p) {
	  struct hp* hp = (struct hp*) p;

    switch (e) {
				case HPACK_EVT_DATA:
				    memcpy(hp->data + hp->offset, buf, len);
						hp->offset += len;
						break;
				default:
				    break;
		}
}

void nghttp2_put_uint32be(uint8_t *buf, uint32_t n) {
	buf[2] = n & 0xFF;
	buf[1] = (n >> 8) & 0xFF;
	buf[0] = (n >> 16) & 0xFF;
}

//  uint32_t x = htonl(n);
//  memcpy(buf, &x, sizeof(uint32_t));

int
encode_header_fields ()
{

}
/*
int
http2_notfound(struct stream* strm, char *buf, int len)
{
    struct hpack_field hp_fld[H2_MAX_HEADER_FIELDS];
		int fc = 0;

		add_header(hp_fld, ":method", val, &fc);

	  // return total size written frame (header + payload)
	  return (H2_HEADER_SIZE + hp.offset + offset);
}
*/

// write http/2 header with information retrieved from the lua header table
int
http2_header(struct stream* strm, char *buf, int len)
{
	  lua_State* T = strm->T;
		struct hpack_field hp_fld[H2_MAX_HEADER_FIELDS];
		struct hpack_encoding hp_enc;
	  struct hp hp = {.data = buf + (sizeof(uint8_t) * H2_HEADER_SIZE), .offset = 0};
//    struct hp hp;
		uint32_t f_sid = 0;
		uint8_t f_typ;
		int offset = 0;
		int fc = 0;
		int status;
	  char const* key;
	  char const* val;
		struct stream* pstrm = NULL;

		memset(buf, 0, (sizeof (uint8_t) * (H2_HEADER_SIZE + 4)));

		// buffer too small, return here and try again next time around
		if (len < BUFFER_SIZE)
		    return 0;

		// check if the stream has an error, write default error response
		if (strm->h2_err > 0) {
		    // http2_error
				return -1;
		}

		if (strm->T) {

		// check if lua header function argument is a table and write error response otherwise
		if (lua_type(T, 1) != LUA_TTABLE) {
				log_dbg(5, "httpd.header: function argument not a lua table");
				//http2_error
				return -1;
		}

		// check type of header (response/promise) by searching for :status pseudo header
		lua_getfield(T, 1, ":status");

		// check if found and process it as a response header
		if (lua_type(T, 3) == LUA_TSTRING) {

				stack_dump(T, "RESPONSE HEAD");
			  f_typ = HEADERS;
				f_sid = strm->h2_sid;

			  val = luaL_checkstring(T, 3);
			  lua_pop(T, 1);

				// throw error if we can't get the :status pseudo header
				if (val == NULL) {
						//http2_error
						return -1;
				}

				// add status header field to the hpack header structure
				add_header(hp_fld, ":status", val, &fc);

				// convert it to a number to check the status code value aritmetically
				status = strtol(val, (char **)NULL, 10);

				// check if the conversion was successful
				if ((status < INT_MIN) || (status > INT_MAX)) {
						//http2_error
						return -1;
				}

				// check the status code value and change the stream status accordingly
				if ((status < 100) || (status >= 400))
						strm->h2_ss == SS_HCLOSED_LOCAL;

	  // otherwise process it as a promise header
 	  } else {
				struct connect *conn = strm->conn;
			  struct stream* pstrm;
			  offset = 4;

				hp.data = buf + (sizeof(uint8_t) * (H2_HEADER_SIZE + 4));

			  lua_pop(T, 1);
				stack_dump(T, "PROMISE HEAD");
				f_typ = PUSH_PROMISE;

				//strm = new_strm(strm->conn, (strm->h2_sid + 1));
//				f_sid = strm->h2_sid;


	      if ((conn->prom_sid == 0) || (strm->h2_sid > conn->prom_sid))
	          conn->prom_sid = strm->h2_sid + 1;
	      else
	          conn->prom_sid  += 2;


//				f_sid = strm->conn->cdbg;
//f_sid = htonl(2);
//f_sid = 0;
//f_sid = htonl(strm->conn->cdbg);
//memcpy(buf + 10, &f_sid, sizeof(f_sid));
//char* x;
//x = buf + (sizeof(uint8_t) * H2_HEADER_SIZE);
//memcpy(&x[1], &f_sid, sizeof(f_sid));
//*(buf + 13) = f_sid & 0xFF;
//*(buf + 12) = (f_sid >> 8) & 0xFF;
//*(buf + 11) = (f_sid >> 16) & 0xFF;

//nghttp2_put_uint32be((uint8_t*)(buf + (sizeof(uint8_t) * H2_HEADER_SIZE ) + 1), (uint32_t)strm->conn->prom_sid);
uint32_t psid = (uint32_t) conn->prom_sid;

*(buf + 12) = psid & 0xFF;
*(buf + 11) = (psid >> 8) & 0xFF;
*(buf + 10) = (psid >> 16) & 0xFF;

//        memcpy(buf + (sizeof(uint8_t) * H2_HEADER_SIZE), &f_sid, 32);
//				memcpy(hp.data + 1, &f_sid, sizeof(f_sid));

//				memcpy(buf + (sizeof(uint8_t) * (H2_HEADER_SIZE)), &f_sid, sizeof(f_sid));
//char* x = buf + (sizeof(uint8_t) * H2_HEADER_SIZE);
				//memcpy(buf + (sizeof(uint8_t) * H2_HEADER_SIZE), &f_sid, sizeof(f_sid));
//				memcpy((x + 1) , &f_sid, sizeof(f_sid));

				lua_getfield(T, 1, ":method");
				val = luaL_checkstring(T, 3);
				add_header(hp_fld, ":method", val, &fc);
				lua_pop(T, 1);

				lua_getfield(T, 1, ":authority");
				val = luaL_checkstring(T, 3);
				add_header(hp_fld, ":authority", val, &fc);
				lua_pop(T, 1);

				lua_getfield(T, 1, ":scheme");
				val = luaL_checkstring(T, 3);
				add_header(hp_fld, ":scheme", val, &fc);
				lua_pop(T, 1);

				lua_getfield(T, 1, ":path");
				val = luaL_checkstring(T, 3);
				add_header(hp_fld, ":path", val, &fc);
				lua_pop(T, 1);
log_dbg(5, "-------- start lua: %s on sid %i", val, strm->conn->prom_sid);
				pstrm = new_strm(strm->conn, strm->conn->prom_sid);
				if (start_lua(pstrm, (char*)val) == -1)
						return -1;

				if ((pstrm->lua_status = lua_run(pstrm->T, pstrm->L, 2)) > LUA_YIELD) {
						log_dbg(5, "error calling Lua handler");
						return -1;
				}
log_dbg(5, "----------- 2 start lua: %s", val);
				pstrm->ss = SS_HEAD;
		}


		// add remaining header fields to the hpack header structure
		while(lua_next(T, -2)) {
			  key = lua_tostring(T, -2);
				val = lua_tostring(T, -1);

				// exclude pseudo headers (headers that starts with ":" chararcer)
				if ((strncmp(key, ":", 1) != 0) && (f_typ == HEADERS))
				    add_header(hp_fld, key, val, &fc);

				lua_pop(T, 1);
		}
} else {
	  f_typ = HEADERS;
		add_header(hp_fld, ":status", "404", &fc);


}
		// pack the hpack_encoding structure with our values
		hp_enc.fld = &(*hp_fld);
		hp_enc.fld_cnt = fc;
		hp_enc.buf = hp.data;
		hp_enc.buf_len = BUFFER_SIZE;
		hp_enc.cb = encode_header;
		hp_enc.priv = &hp;
		hp_enc.cut = 0;

		// encode and return if unsuccessful
		if (hpack_encode(strm->conn->encoder, &hp_enc) < 0) {
			  exit(0);
		    return -1;
		}

		uint8_t flags = 0;
		flags |= FF_END_HEADERS;

		// create frame header for the header type frame
		construct_frame_header((uint8_t *)buf, hp.offset + offset, flags, f_typ, strm->h2_sid);

		if (pstrm)
		    strm->ss = SS_HEAD;
		else
		    strm->ss = SS_SEND;
//		strm->ss = SS_SEND;

		// return total size written frame (header + payload)
		return (H2_HEADER_SIZE + hp.offset + offset);
}

char*
e_strdup(const char* str)
{
    char* dup = strdup(str);
    if (dup == (char*) 0)
        log_ex(NULL, 1, "strdup - %s", strerror(errno));
    return dup;
}

struct stream*
new_strm(struct connect* conn, uint32_t sid)
{
    struct stream* strm;

		if ((strm = calloc(1, sizeof(struct stream))) == NULL)
				return NULL;

		if ((strm->io_buf = malloc(sizeof(char) * BUFFER_SIZE + 1)) == NULL)
		    return NULL;

		strm->h2_sid = sid;

		strm->L = NULL; // take it out maybe?
		strm->T = NULL;
		strm->conn = conn;
		strm->path = NULL;

		strm->next = NULL;
		strm->prev = NULL;

//		for (struct stream* sp = conn->strm_head; sp != NULL; sp = sp->next)
//				log_dbg(5, "B-> strm->h2_sid: %i", sp->h2_sid);

		// if strm is a promise, we heave at least 1 valid strm besides stream id 0
//		if ((sid > 0) && (sid % 2 == 0)) {
//				strm->next = conn->strm_head->next;
//				strm->prev = conn->strm_head;
//				conn->strm_head->next = strm;
//				strm->next->prev = strm;
//			  return strm;
//		}


    if (conn->strm_head == NULL)
		    conn->strm_head = strm;
    else {
		    conn->strm_tail->next = strm;
		    strm->prev = conn->strm_tail;
    }
    conn->strm_tail = strm;
		conn->hs = sid;
		//conn->strm = strm;
//		for (struct stream* sp = conn->strm_head; sp != NULL; sp = sp->next)
//		    log_dbg(5, "A-> strm->h2_sid: %i", sp->h2_sid);
		LIST_INIT(&strm->aio_d);
		return strm;
}



int
new_conn(struct thread* thr)
{
	  struct server* srv = thr->srv;
    struct connect* conn;
    struct stream* strm;
    int len;

		// alloc memory for new connection
		if ((conn = calloc(1, sizeof(struct connect))) == NULL)
				return -1;

		conn->strm_head = NULL;
		conn->strm_tail = NULL;

		// alloc memory for new stream
		if ((conn->strm = new_strm(conn, 0)) == NULL)
		    return -1;

		conn->next_actv = NULL;
		conn->prev_actv = NULL;

		conn->thr = thr;
		thr->conn = conn;

		if ((conn->buf = malloc(sizeof(char) * (BR_SSL_BUFSIZE_BIDI + 1))) == NULL)
			  return -1;

		br_ssl_server_zero(&conn->ssl_sc);

#if SERVER_RSA
#if SERVER_PROFILE_MIN_FS
#if SERVER_CHACHA20
		br_ssl_server_init_mine2c(&conn->ssl_sc, srv->cert, srv->cert_len, &srv->pkey->key.rsa);
#else
		br_ssl_server_init_mine2g(&conn->ssl_sc, srv->cert, srv->cert_len, &srv->pkey->key.rsa);
#endif
#elif SERVER_PROFILE_MIN_NOFS
		br_ssl_server_init_minr2g(&conn->ssl_sc, srv->cert, srv->cert_len, &srv->pkey->key.rsa);
#else
		br_ssl_server_init_full_rsa(&conn->ssl_sc, srv->cert, srv->cert_len, &srv->pkey->key.rsa);
#endif
#elif SERVER_EC
#if SERVER_PROFILE_MIN_FS
#if SERVER_CHACHA20
		br_ssl_server_init_minf2c(&conn->ssl_sc, srv->cert, srv->cert_len, &srv->pkey->key.ec);
#else
		br_ssl_server_init_minf2g(&conn->ssl_sc, srv->cert, srv->cert_len, &srv->pkey->key.ec);
#endif
#elif SERVER_PROFILE_MIN_NOFS
		br_ssl_server_init_minv2g(&conn->ssl_sc, srv->cert, srv->cert_len, &srv->pkey->key.ec);
#else
		br_ssl_server_init_full_ec(&conn->ssl_sc, srv->cert, srv->cert_len, BR_KEYTYPE_EC, &srv->pkey->key.ec);
#endif
#else
#if SERVER_PROFILE_MIN_FS
#if SERVER_CHACHA20
		br_ssl_server_init_minf2c(&conn->ssl_sc, srv->cert, srv->cert_len, &srv->pkey->key.ec);
#else
		br_ssl_server_init_minf2g(&conn->ssl_sc, srv->cert, srv->cert_len, &srv->pkey->key.ec);
#endif
#elif SERVER_PROFILE_MIN_NOFS
		br_ssl_server_init_minu2g(&conn->ssl_sc, srv->cert, srv->cert_len, &srv->pkey->key.ec);
#else
		br_ssl_server_init_full_ec(&conn->ssl_sc, srv->cert, srv->cert_len, BR_KEYTYPE_RSA, &srv->pkey->key.ec);
#endif
#endif

		br_ssl_engine_set_protocol_names(&conn->ssl_sc.eng, &proto_name , 1);
		br_ssl_engine_set_buffer(&conn->ssl_sc.eng, conn->buf, BR_SSL_BUFSIZE_BIDI, 1);

		return 0;
};

void
conntab_update(struct connect* conn)
{
    struct thread* thr = conn->thr;

	  if (thr->conn_head == conn)
		    if (conn->next_actv != NULL)
				    thr->conn_head = conn->next_actv;

	  if (conn->next_actv != NULL) {
		    conn->next_actv->prev_actv = conn->prev_actv;

		    if (conn->prev_actv != NULL)
				    conn->prev_actv->next_actv = conn->next_actv;

		    conn->next_actv = NULL;
	  }

	  if (thr->conn_tail != conn) {
		    thr->conn_tail->next_actv = conn;
		    conn->prev_actv = thr->conn_tail;
		    thr->conn_tail = conn;
	  }

    conn->timestamp = thr->eq->tv;
}

void
conntab_remove(struct connect* conn)
{
    struct thread* thr = conn->thr;
    struct stream* ps = conn->strm;
		struct lua_state_map* Lmap;

    if (conn == NULL)
        return;

    log_dbg(5, "conntab_remove fd: %i\n", conn->fd);
//exit(0);
//		if (conn->ev_r.filter == 1)
//				EQ_DEL(conn->thr->eq, &conn->ev_r, conn->fd);
//		if (conn->ev_w.filter == 1)
//				EQ_DEL(conn->thr->eq, &conn->ev_w, conn->fd);

		if (conn->ev.filter & EV_READ)
		    EQ_DEL(conn->thr->eq, &conn->ev, conn->fd, EV_READ);
		if (conn->ev.filter & EV_WRITE)
				EQ_DEL(conn->thr->eq, &conn->ev, conn->fd, EV_WRITE);

    close(conn->fd);

    //lthread_remove(thr->lua_map->L, conn->strm->T);


    for (struct stream* strm = ps; strm;) {
        reset_headers(strm);
        if (strm->T) {
            lthread_remove(strm->L, &strm->T);
            strm->T = NULL;
        }
        if (strm->fd > -1) {
//					  EQ_DEL(conn->thr->eq, strm->fd, EV_READ, strm);
//						EQ_DEL(conn->thr->eq, strm->fd, EV_READ, strm);
//            close(strm->fd);
            //strm->fd = -1;
        }

				ps = strm->next;

				if (ps)
						free(strm);

        strm = ps;
    }

     reset_headers(conn->strm);
     conn->strm = calloc(1, sizeof(struct stream));


    if (thr->srv->cert_len > 0) {
        log_dbg(5, "\n\n\n\n\nIIIIIIIIIIIIIIII DISCONNECT FD: %i\n\n\n\n\n cdbg: %i", conn->fd, conn->prom_sid);
        br_ssl_engine_flush(&conn->ssl_sc.eng, 0);
		}

		SIMPLEQ_FOREACH(Lmap, &conn->thr->L_map, next)
        stack_dump(Lmap->L, "MAIN STATE");

    if (thr->conn_head == conn)
        thr->conn_head = conn->next_actv;
    else if (conn->prev_actv)
        conn->prev_actv->next_actv = conn->next_actv;

    if (thr->conn_tail == conn)
        thr->conn_tail = conn->prev_actv;
		else
				conn->next_actv->prev_actv = conn->prev_actv;

//    conn->r_ev = ssl_read;
//    conn->w_ev = ssl_write;

    //conn->fd = -1;
    conn->timestamp = 0;
    conn->next_actv = NULL;
    conn->prev_actv = NULL;
    //conn->event = conn_read;
    //conn->event = rw_io;
//    conn->r_ev = ssl_read;
//    conn->w_ev = ssl_write;


    //conn->io_rbuf = NULL;
    //conn->io_len = 0;
    //conn->rb = 0;

    //free(ps->io_buf);  ///// danger!!
    //if (ps)
    //free(ps);

    if (thr->conn != conn) {
			  log_dbg(5, "NOT EQ");
        free(conn);
		}


    //conn->status = 0;
		conn->cs = CS_INIT;
		conn->hs = 0;

		conn->ev.cb[1] = lhttpd_noop;
		conn->ev.cb[2] = lhttpd_noop;
		//conn->ev.cb[] = {lhttpd_noop, lhttpd_noop, lhttpd_noop};

//remove
//    free(ps->io_buf);  ///// danger!!
//    free(ps);  ///// danger!!
//    free(conn);  ///// danger!!
//    return; ///// danger!!
//remove
/*
    if (thr->conn->status > 1) {
        log_dbg(5, "reusing conn %p\n", ps->io_buf);
        ps->io_lnr = 0;
        ps->io_lwm = 0;
        ps->io_hwm = 0;
        ps->path = NULL;
        ps->head = NULL;
        ps->io_buf[0] = '\0';

        conn->strm = ps;
        conn->thr->conn = conn;
    } else if (conn != thr->conn) {
        log_dbg(5, "== Freeing CONNECTION, STREAM, BUFFER ==");
        free(ps->io_buf);
        free(ps);
        free(conn);
    }
*/
}

void
conntab_create(struct edata *ev)
{
	  struct thread* thr = ev->ctx;
		struct connect* conn = thr->conn;
    struct server* srv = thr->srv;
		socklen_t len = sizeof(struct sockaddr_storage);
		int ovtval = 1;
		char c;

//		if (NCPU > 1)
//		    EQ_ADD(thr->eq, &thr->ev[0], srv->fd, EV_READ, conntab_create, thr, 1);


log_dbg(5, "FFFFUU %i", srv->fd);

		if ((conn->fd = accept(srv->fd, (struct sockaddr *)&(conn->ss), &len)) == -1) {

			  log_dbg(5, "YYYY");
				if (!(errno == EINTR || errno == ECONNABORTED))
						log_ex(NULL, 5, "accept error - %s", strerror(errno));
				log_dbg(5, "WTFFFFFF");
				return;
		}

		if (NCPU > 1) {
			  //EQ_ADD(srv->thr[0].eq, &srv->thr[0].ev[0], srv->fd, EV_READ, conntab_create, &srv->thr[0], 1);
				if ((srv->ti +=1) >= NCPU)
				    srv->ti = 0;

log_dbg(5, "gg");
//srv->ti += 1;
log_dbg(5, "gg2 %i", srv->ti);
log_dbg(5, "% filter of srv->ti %i", srv->thr[srv->ti].ev[0].filter);



				EQ_ADD(srv->thr[srv->ti].eq, &srv->thr[srv->ti].ev[0], srv->fd, EV_READ, conntab_create, &srv->thr[srv->ti], 1);

			//	EQ_ADD(thr->eq, &thr->ev[0], srv->fd, EV_READ, conntab_create, thr, 1);

				log_dbg(5, "gg3");
//		    assert(write(srv->thr[srv->ti].pfd[1], "c", 1) == 1);

				u_int64_t eval = 1;
				assert(write(srv->thr[srv->ti].pfd[1], &eval, sizeof(eval)) == sizeof (eval));
	  }



    log_dbg(5, "T ADDING CONNECTION     sfd: %i\n", conn->fd);

    fcntl(conn->fd, F_SETFL, fcntl(conn->fd, F_GETFL, 0) | O_NONBLOCK);

	  if (thr->conn_head == NULL)
        thr->conn_head = thr->conn;
		else {
			  thr->conn_tail->next_actv = thr->conn;
			  thr->conn->prev_actv = thr->conn_tail;
		}
		thr->conn_tail = conn;

    conn->timestamp = thr->eq->tv;

		conn->cs = CS_RECV;

    conntab_update(conn);


    br_ssl_server_reset(&conn->ssl_sc);

    log_dbg(5, "SSL: new connect\n");
    return conn_io(conn);
}

void
thread_wakeup(struct edata *ev) {
	  struct thread *thr = (struct thread *) ev->ctx;
		struct server *srv = thr->srv;
	  int ac = thr->aio->ac;
		char c;
		int id = -1;
		u_int64_t eval = 0;
		int rv;

		if (ev->filter != 0) {
			  rv = read(ev->fd, &eval, sizeof(eval));
			  if (rv != sizeof (eval)) {
					  log_dbg(5, "ERRORRR size mismatch");
						exit(0);
						return;
				}
		}


log_dbg(5, "REARMREARMREARM BOOOM %i ac %i  wait: %i", eval, ac, thr->aio->wait);


if ((thr->aio->wait == 1) && (eval > 0)) {
	while (ac > 0) {
			struct aio_data *aio_d[MAX_AIO];

			thr->aio->wait = 0;
			int n = thr->aio->ac;
			thr->aio->ac = 0;

			int r;

			r = lh_aio_reap(thr->aio, aio_d, ac);

			log_dbg(5, "\n\n\n\n\n r %i \n\n\n\n\n\n", r);

			if (r <= 0)
					break;

			for (int i = 0; i < r; i++)
					lh_aio_dispatch(aio_d[i]);

			ac -= r;
	}


}

/*
if ((thr->aio->wait == 1) && (thr->aio->ac > 0)) {
		struct aio_data *aio_d;
		thr->aio->wait = 0;
		int n = thr->aio->ac;
		thr->aio->ac = 0;

		for (int i = 0; i < n; i++) {
		log_dbg(5, "FFF2");

//					aio_d = lh_aio_reap(ii, srv->thr[i].aio->alist);
    aio_d = lh_aio_reap(i, thr->aio->alist);

		if (aio_d == NULL) {
				log_dbg(5, "NULL?");
				//exit(0);
				log_dbg(5, "error reaping aio request");
				continue;
		}

		lh_aio_dispatch(aio_d);

		}


		aio_d->ready = 1;
}
*/
}

void*
serve(void *thread) {

    struct thread* thr = (struct thread*) thread;
    struct server* srv = thr->srv;
    struct equeue* eq = thr->eq;
		struct edata* ev;
		int rv;


		//EQ_ADD(eq, &thr->ev[0], srv->fd, EV_READ, conntab_create, thr, ((NCPU == 1) ? 0: 1));

    for (;;) {

        log_dbg(5, "\nTIMER: %p  thr: %p\n", thr->conn_head, thr);

				EQ_POLL(eq, (thr->conn_head? (srv->timeout* 1000 - ((eq->tv - thr->conn_head->timestamp)/1000000)): -1));

				log_dbg(5, "\nSERVE:  thr: %p\n", thr);

				// re-arm aio signal and resume processing
//				if (thr->aio->ar > 0) {
//				    EQ_ADD(thr->eq, &thr->ev[1], srv->aid, EV_SIGNAL, lh_aio_ready, thr, 1);
//						lh_aio_dispatch(srv->aid, thr->aio->alist);
//						thr->aio->ar = 0;
//				}

				//if (thr->aio->ac > 0) {
			  if ((thr->aio->nc > 0) && (thr->aio->wait == 0)) {
					  log_dbg(5, "SCHEDULE SOME MORE: %i", thr->aio->nc);
//?						thr->aio->ac = thr->aio->nc;
						//for (int i = 0; i < 16; i++)
						//thr->aio->alist[i] = thr->aio->nlist[i];

//?						memcpy(thr->aio->alist, thr->aio->nlist, 160*16);
log_dbg(5, "oh no");
//?						thr->aio->nc = 0;
//EQ_ADD(thr->eq, &thr->ev[1], srv->aid, EV_SIGNAL, lh_aio_ready, thr, 1);
			//			lh_aio_schedule(srv->aid, thr);
						lh_aio_schedule(thr->aio, thr);
						log_dbg(5, "oh no2");
					  //thr->aio->ac = 0;
				}
log_dbg(5, "int");
        while (thr->conn_head && ((eq->tv - (long)(srv->timeout*1000000000)) >= thr->conn_head->timestamp)) {
            //log_dbg(5, "conn_head: %p", thr->conn_head);
            conntab_remove(thr->conn_head);
        }

				if (thr->conn->cs != CS_INIT) {
            //log_dbg(5, "preallocating here\n");
            if((new_conn(thr)) < 0)
                log_ex(srv, 1, "error preallocating connection - %s", strerror(errno));
        }
        log_dbg(5, "end loop\n");
    }
    return NULL;
};


//////////////////
//////////////////

/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////
static void
strdecode(char* str)
{
    for (char *from = str ; *from != '\0'; ++str, ++from ) {
        if ( from[0] == '%' && isxdigit( from[1] ) && isxdigit( from[2] ) ) {
            char buf[] = {from[1], from[2], '\0'};
            *str = (char)strtol(buf, NULL, 16);
            from += 2;
        } else
            *str = *from;
    }
    *str = '\0';
}

static void
strencode( char* to, int tosize, char* from )
{
    int tolen;

    for (tolen = 0; *from != '\0' && tolen + 4 < tosize; ++from) {
	      if (isalnum(*from) || strchr( "/_.-~", *from ) != (char*) 0) {
	          *to = *from;
	          ++to;
	          ++tolen;
	      } else {
	          (void) sprintf( to, "%%%02x", (int) *from & 0xff );
	          to += 3;
	          tolen += 3;
	      }
	  }
    *to = '\0';
}


int
process_http2(struct connect* conn)
{
	return 0;
}


int
check_request(const char* buf, int len)
{
    char* c;

    if ((c = strnstr(buf, "\r\n\r\n", len)))
        return ((c - buf) + 4);
    if ((c = strnstr(buf, "\n\n", len)))
        return ((c - buf) + 2);

    return 0;
}

int
parse_http(struct stream* strm, char* buf, int len)
{
    struct connect* conn = strm->conn;
		struct lua_handler* lh;
    int idx = 0;
		char *c;

	  while ((c = memchr(buf, '\n', len - idx)) != NULL) {

        idx = (c - buf) + 1;

        *c = '\0';

				if (*(c-1) == '\r')
            *(c-1) = '\0';

				if (strm->T == NULL) {
            char* path;

            if (c - buf < 1)
                goto error;

            strm->method = buf;
            strm->method += strspn(strm->method, " \t");

            if ((path = strpbrk(strm->method, " \t")) == NULL)
                goto error;

            *path++ = '\0';

						log_dbg(5, "METHOD: %s", strm->method);

						if (strcasecmp(strm->method, "HEAD") == 0) {
								strm->http_method = HEAD;
						} else if (strcasecmp(strm->method, "GET") == 0) {
								log_dbg(5, "method: GET\n");
								strm->http_method = GET;
						} else if (strcasecmp(strm->method, "POST") == 0) {
								log_dbg(5, "method: POST\n");
								strm->http_method = POST;
						} else {
								log_dbg(5, "HTTP error: UNSUPPORTED_METHOD");
								goto error;
						}

            path += strspn(path, " \t");
            while (path[1] == '/')
                path++;

            if (path >= c - 1)
                goto error;

            if ((conn->protocol = strpbrk(path, " \t")) == NULL)
                goto error;

            *conn->protocol++ = '\0';
            conn->protocol += strspn(conn->protocol, " \t");

            if (strcasecmp(conn->protocol, "HTTP/1.1") == 0) {
                conn->http_11 = 1;
                log_dbg(5, "*** HTTP/1.1\n");
            } else if (strcasecmp(conn->protocol, "HTTP/1.0") == 0)
                log_dbg(5, "*** HTTP/1.0\n");
            else {
                log_dbg(5, "unknown protocol");
                conn->protocol = NULL;
                goto error;
            }

						strdecode(path);
						if (start_lua(strm, path) == -1)
								goto error;

						if (strm->T == NULL) {
								strm->ss = SS_HEAD;
								return len;
						}

						lua_pushstring(strm->T, strm->method);
						lua_setfield(strm->T, -2, "method");
						lua_pushstring(strm->T, path);
						lua_setfield(strm->T, -2, "path");

        } else {
						char *key;
						char *val;

						stack_dump(strm->T, "STARTING THREAD WITH LUA");
						log_dbg(5, "strm->sid: %i", strm->h2_sid);
						log_dbg(5, "c: %s", c);
						log_dbg(5, "buf :%s", buf);
						log_dbg(5, "%i", (c-buf));

						// check if the request is done
						if (c - buf <= 1) {

							  if ((strm->lua_status = lua_run(strm->T, strm->L, 2)) > LUA_YIELD) {
						 				log_dbg(5, "error calling Lua handler");
										goto error;
								}

								break;
            }

						key = buf;
            key += strspn(key, " \t");

            if ((val = strchr(key, ':')) == NULL || val == key)
                goto error;

            *val++ = '\0';
            val += strspn(val, " \t");

//						if (strcasecmp(key, "connection") == 0 && strcasecmp(val, "keep-alive") == 0)
//                conn->keep_alive = 1;
						if (strcasecmp(key, "connection") == 0 && strcasecmp(val, "close") == 0)
								conn->conn_close = 1;

						lua_pushstring(strm->T, val);
						lua_setfield(strm->T, -2, key);

#if 0
            else if (strcasecmp(key, "connection") == 0 && strcasecmp(val, "upgrade") == 0)
                conn->upgrade = 1;
            else if (strcasecmp(key, "upgrade") == 0 && strcasecmp(val, "h2c") == 0) {
								conn->cs = CS_ERROR;
            }
#endif
            log_dbg(5, "adding header# %s: %s.\n", key, val);
        }
				buf += idx;
    }
    return len;

error:
    strm->ss = SS_ERROR;
		return -1;
}

// update connection settings with id values received from peer
int
update_settings(struct connect* conn, char* data, uint32_t len)
{
	  size_t idx = 0;

	  while (idx < len) {
			  uint16_t id = 0;
			  uint32_t val;

			  memcpy(&id, (data + idx), sizeof(uint16_t));
			  memcpy(&val, (data + idx + 2), sizeof(uint32_t));
				idx += 6;
log_dbg(5, "SETTINGS VALUE RECEIVED: %i", id);
				// update settings based on id value
        switch (id) {
		    case 1:
		        conn->h2_set.header_table_size = val;
				    hpack_resize(&conn->encoder, MIN(val, 65535));
				    break;
		    case 2:
				    if (val != 0 && val != 1) {
								conn->h2_err = PROTOCOL_ERROR;
				        return -1;
		        }
						log_dbg(5, "PUSH IT ALL");
						exit(0);
				    conn->h2_set.enable_push = val;
				    break;
		    case 3:
				    conn->h2_set.max_concurrent_streams = val;
				    break;
		    case 4:
				    if (val > ((1U << 31) - 1)) {
						    conn->h2_err = FLOW_CONTROL_ERROR;
						    return -1;
				    }
				    conn->h2_set.window_size = val;
				    break;
		    case 5:
				    if (val < (1 << 14) || val > ((1 << 24) - 1)) {
					      conn->h2_err = PROTOCOL_ERROR;
					      return -1;
				    }
				    conn->h2_set.max_frame_size = val;
				    break;
		    case 6:
				    conn->h2_set.max_header_list_size = val;
				    break;
		    default:
				    break;
		    }
    }
		// success
		return 0;
}

int
check_ss(struct stream* strm, uint8_t f_typ)
{
	  switch (strm->h2_ss) {
		case SS_IDLE:
		    if ((f_typ == HEADERS) || (f_typ == PRIORITY))
				    return 0;

				break;
		case SS_RESERVED_LOCAL:
		    if ((f_typ == RST_STREAM) || (f_typ == PRIORITY) || (f_typ == WINDOW_UPDATE))
				    return 0;

				break;
		case SS_RESERVED_REMOTE:
		    if ((f_typ == HEADERS) || (f_typ == RST_STREAM) || (f_typ == PRIORITY))
				    return 0;

				break;
		case SS_HCLOSED_REMOTE:
		    if ((f_typ == WINDOW_UPDATE) || (f_typ == PRIORITY) || (f_typ == RST_STREAM))
				    return 0;

				strm->h2_err = STREAM_CLOSED;
				return 1;
		case SS_CLOSED:
				if ((f_typ == WINDOW_UPDATE) || (f_typ == RST_STREAM) || (f_typ == PRIORITY))
				    return 0;

				break;
		case SS_HCLOSED_LOCAL:
		case SS_OPEN:
		default:
		    return 0;
    }

		strm->conn->h2_err = PROTOCOL_ERROR;
		return -1;
}

int
process_frame(struct stream *strm, struct h2_frame frm, char* data)
{
		struct connect *conn = strm->conn;
		int rv;

    log_dbg(5, "PROCESS FRAME");
		log_dbg(5, "LEN: %i", frm.f_len);
		log_dbg(5, "FLG: %i", frm.f_flg);
		log_dbg(5, "TYP: %i", frm.f_typ);
		log_dbg(5, "SID: %i", frm.f_sid);

log_dbg(5, "sid: %i strm->h2_ss: %i", strm->h2_sid, strm->h2_ss);
//	  if (strm->h2_ss == IDLE)
//	      log_dbg(5, "IDLE, look at stream status");


	  if (frm.f_sid != 0) {
		    rv = check_ss(strm, frm.f_typ);

				log_dbg(5, "strm->h2_ss: %i", strm->h2_ss);
				if (rv < 0) {
					  log_dbg(5, "unknown stream state change");
						//exit(0);
						return -1;
				} else if (rv > 0)
						log_dbg(5, "HEREHEHRHEHRHEHRHEHRHEHRHEHRHE");
		}

		if (frm.f_typ == SETTINGS) {
				log_dbg(5, "GOT SETTINGS strm->sid %i f_sid %i", strm->h2_sid, frm.f_sid);
				// if settings dont come on stream id 0, it's a protocol error
				if (strm->h2_sid != 0) {
						conn->h2_err = PROTOCOL_ERROR;
						return -1;

				// if length is not a multiple of 6, it's a size error
				} else if (frm.f_len % 6 != 0) {
					  conn->h2_err = FRAME_SIZE_ERROR;
						return -1;

				// if it's the end of a stream with settings, length must be 0 and we must send back settings confirmation
		 	  } else if ((frm.f_flg & 1) != 0) {
				    if (frm.f_len != 0) {
							  conn->h2_err = FRAME_SIZE_ERROR;
							  return -1;
						}
				// let's process the settings frame
		    } else {
log_dbg(5, "going to process");
						// process settings
					  if (update_settings(conn, data, frm.f_len) < 0)
								return -1;
log_dbg(5, "oh no");
						// flag to send settings
						log_dbg(5, "got settings flag");
						conn->send_settings = 1;
				}
				return 1;
		} else if (frm.f_typ == WINDOW_UPDATE) {
			    uint32_t inc;

				  if (frm.f_len != 4) {
						  conn->h2_err = FRAME_SIZE_ERROR;
						  return -1;
          }

					//inc = ntohl(*(uint32_t *)data) & 0x7FFFFFFF;
					inc = (*(uint8_t*)&data[0] << 24) | (*(uint8_t*)&data[1] << 16) | (*(uint8_t*)&data[2] << 8) | (*(uint8_t*)&data[3]);

					if (frm.f_sid == 0) {
							if (inc == 0) {
								  conn->h2_err = PROTOCOL_ERROR;
								  return -1;
							} else if ((conn->h2_set.window_size + inc) > ((1U << 31) - 1)) {
									conn->h2_err = FLOW_CONTROL_ERROR;
								  return -1;
				      }
							conn->h2_set.window_size += inc;
							return 1;
					}
					if (strm->h2_ss == SS_CLOSED) {
						  conn->h2_err = PROTOCOL_ERROR;
						  return -1;
					} else if (inc == 0) {
							strm->h2_err = PROTOCOL_ERROR;
							strm->h2_ss = SS_CLOSED;
					} else if ((strm->window_size + inc) > ((1U << 31) - 1))
						  strm->h2_err = FLOW_CONTROL_ERROR;

					strm->window_size += inc;
					return 1;

	  // PRIORITY frame type receiver
	  } else if (frm.f_typ == PRIORITY) {

				  // stream id cannot be 0, protocol error as per rfc7540
				  if (frm.f_sid == 0) {
					    conn->h2_err = PROTOCOL_ERROR;
							return -1;
					}

					// priority frame length is 5 octets, check
					if (frm.f_len != 5) {
					    conn->h2_err = FRAME_SIZE_ERROR;
							return -1;
					}

					/* TODO: set priority data to stream */
	        //set_priority(strm, frm.f_sid, (uint8_t *)data, IDLE);

					return 1;
		} else if (frm.f_typ == CONTINUATION) {
					if ((frm.f_flg & (FF_END_STREAM | FF_PADDED | FF_PRIORITY)) != 0) {
							conn->h2_err = PROTOCOL_ERROR;
							return -1;
					}

					return 1;
		} else if (frm.f_typ == HEADERS) {
				  struct connect* conn = strm->conn;
				  int rv;
					char* key = NULL;
					char* val = NULL;
					size_t dec_len = frm.f_len;
					struct hpack_decoding dec;

log_dbg(5, "HEADERS??");
					if ((frm.f_sid == 0) || (frm.f_sid % 2 != 1)) {
						  conn->h2_err = PROTOCOL_ERROR;
						  return -1;
					} //else
					// TODO: Check number of open streams

					conn->cont_sid = (frm.f_flg & FF_END_HEADERS) == 0 ? frm.f_sid: 0;
					strm->h2_flg = frm.f_flg;

					// if it's padded adjust the encoded block
					if (frm.f_flg & FF_PADDED) {
							dec_len -= (*(uint8_t *)data) + 1;
							data += 1;
					}

					// check if we need to reprioritize and adjust the encoded block
					if (frm.f_flg & FF_PRIORITY) {

						  // check for proper priority length and throw error if bogus
							if (dec_len < 5) {
									conn->h2_err = PROTOCOL_ERROR;
									return -1;
							}

							/* TODO: set priority data to stream */
							// set_priority(strm, frm.f_sid, (uint8_t *)data, OPEN);

							// adjust the decoding info
							dec_len -= 5;
							data += 5;
					}

					dec.blk = data;
					dec.blk_len = dec_len;
					dec.buf = strm->conn->hb;
					dec.buf_len = INIT_HB_BUF_SIZE;
					dec.cb = NULL;
					dec.priv = strm->conn;
					dec.cut = !(frm.f_flg & FF_END_HEADERS);

					while((rv = hpack_decode_fields(conn->decoder, &dec, (const char **)&key, (const char **)&val)) == HPACK_RES_FLD) {
						  log_dbg(5, "HEADER: %s %s", key, val);

							if (strcasecmp(key, ":method") == 0) {
							    strm->method = val;
									if (strcasecmp(strm->method, "HEAD") == 0) {
											strm->http_method = HEAD;
									} else if (strcasecmp(strm->method, "GET") == 0) {
											log_dbg(5, "method: GET\n");
											strm->http_method = GET;
									} else if (strcasecmp(strm->method, "POST") == 0) {
											log_dbg(5, "method: POST\n");
											strm->http_method = POST;
									} else
											log_dbg(5, "UNSUPPORTED_METHOD");

							} else if (strcasecmp(key, ":scheme") == 0)
									strm->scheme = val;
							else if (strcasecmp(key, ":path") == 0) {

								  // strdecode(path);
								  if (start_lua(strm, val) == -1)
										  return -1;

									if (strm->T == NULL)
									    continue;

									lua_pushstring(strm->T, val);
									lua_setfield(strm->T, -2, key);
							} else if (strcasecmp(key, ":authority") == 0) {
							    strm->authority = val;
							// pseudo headers done
						} else if (strm->T) {
									lua_pushstring(strm->T, val);
									lua_setfield(strm->T, -2, key);
							}
					}
log_dbg(5, "RV IS :%i",rv);
					switch (rv) {
						  case HPACK_RES_BLK:
							    log_dbg(5, "HPACK_RES_BLK expecting CONTINUATION");
							    return 1;
							case HPACK_RES_OK:
log_dbg(5, "got header on sid %i", strm->h2_sid);
									if (strm->T == NULL) {
										  strm->ss = SS_HEAD;
									    return 1;
									}

									lua_pushstring(strm->T, strm->method);
									lua_setfield(strm->T, -2, ":method");
									lua_pushstring(strm->T, strm->authority);
									lua_setfield(strm->T, -2, ":authority");
									lua_pushstring(strm->T, strm->scheme);
									lua_setfield(strm->T, -2, ":scheme");

									if ((strm->lua_status = lua_run(strm->T, strm->L, 2)) > LUA_YIELD) {
											log_dbg(5, "error calling Lua handler");
											strm->h2_err = INTERNAL_ERROR;
											strm->h2_ss = SS_CLOSED;
											return 1;
									}

									if (frm.f_flg & FF_END_STREAM)
									    strm->h2_ss = SS_HCLOSED_REMOTE;
									else
									    strm->h2_ss = SS_OPEN;

							    //strm->ss = SS_HEAD;

									return 1;
							case HPACK_RES_SKP:
							case HPACK_RES_BIG:
							default:
							    //error
									conn->h2_err = INTERNAL_ERROR;
									return -1;
					}

		} else if (frm.f_typ == PING) {
				if (frm.f_len != 8) {
						conn->h2_err = FRAME_SIZE_ERROR;
						return -1;
				} else if (frm.f_sid != 0) {
					  conn->h2_err = PROTOCOL_ERROR;
					  return -1;
				} else if ((frm.f_flg & 1) == 0) {
					  // send_ping;
					  conn->send_ping = 1;
						conn->ping_data = data + H2_HEADER_SIZE;
				}
		} else if (frm.f_typ == GOAWAY) {
			  if (frm.f_len >= 8) {
						log_dbg(5, "Received GOAWAY (%d): %.*s", ntohl(*(uint32_t *)(data + H2_HEADER_SIZE + 4)), (frm.f_len - 8), ((data + H2_HEADER_SIZE + 8)));
						log_dbg(5, "Received GOAWAY %s",  (data + H2_HEADER_SIZE + 8));
						log_dbg(5, "Received GOAWAY %s", (data + 8));
						//exit(0);
				}
			  return -1;
		} else if (frm.f_typ == RST_STREAM) {
        if (frm.f_len != 4) {
	          conn->h2_err = FRAME_SIZE_ERROR;
	          return -1;
        } else if (frm.f_sid == 0) {
	          conn->h2_err = PROTOCOL_ERROR;
	          return -1;
        } else if (strm == NULL || strm->h2_ss == SS_CLOSED) {
	          if (frm.f_sid <= conn->hs) {
							  conn->h2_err = PROTOCOL_ERROR;
		            return -1;
	          }
        } else if (strm->h2_ss == SS_IDLE) {
					  conn->h2_err = PROTOCOL_ERROR;
					  return -1;
        } else {
	          log_dbg(5, "RST_STREAM: id %u, err %u", frm.f_sid, ntohl(*(uint32_t *)data));
						exit(0);
	   				strm->h2_ss = SS_CLOSED;
        }
		} else if (frm.f_typ == DATA) {

				// return 0 because the rest of the processing needs to be done by lua handler
				return 0;
		}

		// done processing the frame
		return 1;
}

int
http2_read(struct connect* conn, char* buf, int len)
{
	  struct stream* strm;
    struct h2_frame frm;
    uint8_t pad = 0;
    int idx = 0;
		int rv;

		// initial state, waiting HTTP/2 preface
    if (conn->h2_state == H2_WAITING_MAGIC) {
        if (len < CLIENT_MAGIC_LEN)
            return 0;

				// check if we have a valid HTTP/2 preface
        if (memcmp(CLIENT_MAGIC, buf, CLIENT_MAGIC_LEN) != 0)
				    goto error;

				// we got the preface, advance the index
				idx += CLIENT_MAGIC_LEN;
				conn->h2_state = H2_WAITING_SETTINGS;
    }

		// this loops over the buffer and decodes/processes frame by frame
		do {
			  // parse frame header
				if (conn->f_len == 0) {

			      // do we have a full header
			      if ((idx + H2_HEADER_SIZE) > len)
					      return idx;

				    // decode frame header lengh settings
			      frm.f_len = (*(uint8_t*)&buf[idx] << 16) | (*(uint8_t*)&buf[idx + 1] << 8) | (*(uint8_t*)&buf[idx + 2]);

				    // do we have the full frame, now that we know its length
				    if ((idx + H2_HEADER_SIZE + frm.f_len) > len)
						    return idx;

				    // decode remaining frame header settings
            frm.f_sid = (*(uint8_t*)&buf[idx + 5] << 24) | (*(uint8_t*)&buf[idx + 6] << 16) | (*(uint8_t*)&buf[idx + 7] << 8) | (*(uint8_t*)&buf[idx + 8]);
            frm.f_typ = *(uint8_t*)&buf[idx + 3];
            frm.f_flg = *(uint8_t*)&buf[idx + 4];

						//frm.f_sid = frm.f_sid & ((1u << 31) -1);

				    // if the http/2 state is waiting for settings, make sure we got the settings frame without the ack
				    if (conn->h2_state == H2_WAITING_SETTINGS) {
								if ((frm.f_typ != SETTINGS) || (frm.f_flg & 1 != 0)) {
										conn->h2_err = PROTOCOL_ERROR;
								    goto error;
						    // we got the settings frame we were waiting, change state to idle
						    } else
								    conn->h2_state = H2_IDLE;
				    }

				    // attempt to find a stream based on stream id
				    strm = h2_find_stream(conn, frm.f_sid);

				    // if we didnt find an existing stream, create new
				    if (strm == NULL) {
							  log_dbg(5, "STRM NOT FOUND frm.f_sid %i", frm.f_sid);
						    strm = new_strm(conn, frm.f_sid);
                log_dbg(5, "NOW FOUND STRM NOT FOUND");
				    // if we found the stream, check to see if we're expecting a continuation
				    } else if ((conn->cont_sid != 0) && (conn->cont_sid == frm.f_sid) && (frm.f_typ != CONTINUATION)) {
						    conn->h2_err = PROTOCOL_ERROR;
						    goto error;
				    }

				    // we're going to receive more than we can handle, send error to client
			      if (frm.f_len > h2_settings.max_frame_size) {
								conn->h2_err = FRAME_SIZE_ERROR;
				    }

				    // advance index, we got the header
				    idx += H2_HEADER_SIZE;

						//check if frame is allowed in current state
						rv = process_frame(strm, frm, &buf[idx]);

						// do we have an error while processing the frame
						if (rv < 0)
								goto error;
//conn->strm = strm;

						// frame fully processed, check if we it's a control frame and need to reply or move on to the next one
						if (rv == 1) {
						    idx += frm.f_len;

								if (conn->send_ping == 1)
										break;

								continue;
						}

						// note how much data remains to be processed
						conn->f_len = frm.f_len;
						conn->strm = strm;
				}
				log_dbg(5, "p: %p", conn->strm);
log_dbg(5, "going to lev_read %i strm->T %p", conn->f_len, conn->strm->T);
				// read payload data from the conn buffer and pass it to lua

//if (strm->lua_status != 0) {
	    log_dbg(5, "T");
				rv = lev_read(conn->strm, &buf[idx], conn->f_len);

				if (conn->strm->ss & SS_WAIT)
						conn->cs |= CS_WAIT;

				// advance the index
				idx += rv;

				// if we have more to read, try again later
				if ((conn->f_len -= rv) > 0)
				    break;


		// repeat and process another frame if we still have data in buffer
		} while (idx < len);

		// return index of how much data we read from the conn buffer
		return idx;

// frame error
error:
		//conn->status = ERROR;
    return len;
}


int
http_read(struct connect* conn, char* buf, int len)
{
	  struct stream* strm = conn->strm;
		int idx = 0;
		int rv = 0;
		char* c;

	  // initial state, checking for header length
	  if (strm->ss == SS_INIT) {

				// atempt to start http/2 via alpn
			  if (conn->http_protocol == 0) {
					  char const* alpn;

					  alpn = br_ssl_engine_get_selected_protocol(&conn->ssl_sc.eng);
					  if (alpn && (memcmp(proto_name, alpn, strlen(proto_name)) == 0)) {
								if (h2_init(conn) < 0)
								    return -1;
								return http2_read(conn, buf, len);
						}
						conn->http_protocol = HTTP11;
				}

        if ((c = strnstr(buf, "\r\n\r\n", len)))
						rv = parse_http(strm, buf, ((c - buf) + 4));
        else if ((c = strnstr(buf, "\n\n", len)))
						rv = parse_http(strm, buf, ((c - buf) + 2));
				else if (len > BUFFER_SIZE) {
				    strm->ss = SS_ERROR;
						return 0;
				} else
				    return 0;
		}

		rv += lev_read(strm, (buf + rv), (len - rv));

		if ((strm->T != NULL) && (strm->lua_status != LUA_YIELD))
				strm_reset(strm);

		change_state(conn, strm->ss);
		return rv;
} //f


int
http_header(struct stream* strm, char *buf, int len)
{
		lua_State* T = strm->T;
		int hlen = 0;
		int slen = 0;

		char const* key;
		char const* val;

		//if (len > BUFFER_SIZE)
		//    return 0;

		if (strm->T) {
		stack_dump(T, "HTTP HEADER");

		if (lua_type(T, 1) != LUA_TTABLE) {
		    log_dbg(5, "httpd.header: function argument not a lua table");
				stack_dump(T, "AHA");
				goto err;
		}

		lua_getfield(T, 1, ":status");
		val = luaL_checkstring(T, 3);
		lua_pop(T, 1);

		hlen = snprintf(buf, (len - hlen), "HTTP/1.1 %s\r\n", val);
		if (hlen >= len)
		    goto err;

		while(lua_next(T, -2)) {
				key = lua_tostring(T, -2);
				val = lua_tostring(T, -1);
				if (strcasecmp(key, ":status") != 0)
			      hlen += snprintf(&buf[hlen], (len - hlen), "%s: %s\r\n", key, val);
		    lua_pop(T, 1);
				if (hlen >= len)
				    goto err;
    }
	  }

		if (strm->http_method != POST) {
		    hlen += snprintf(&buf[hlen], (len - hlen), "\r\n");

		    if (hlen >= len)
			      goto err;
		}
		strm->ss = SS_SEND;

		return hlen;

err:
    strm->ss = SS_ERROR;
		return 0;
}

void
conn_io(struct connect* conn)
{
	  struct thread* thr = conn->thr;
		int sendrec = 0;
		int recvrec = 0;
		char* buf;
		size_t len;

		// this loop has two sections, setting up connection r/w events and getting app data in and out of the sll engine.
		// it tries to execute all states of the ssl engine before it needs to return and wait for any connection events.
		// once data is retrived or injected into the engine, it checks if any new events need to be added before it returns.
		// in addition to ssl states, is also checks for various app states and returns as required
log_dbg(5, "=====================");
    // gracefully close, send close_notify
    if (conn->cs & CS_CLOSE) {
				br_ssl_engine_close(&conn->ssl_sc.eng);
				conntab_remove(conn);
		    return;
    }

		while (!(conn->cs & CS_ERROR)) {

		    conn->ssl_state = br_ssl_engine_current_state(&conn->ssl_sc.eng);
        log_dbg(5, "SSL STATE: %i conn->status %i, conn->fd: %i", conn->ssl_state, conn->cs, conn->fd);
				if (conn->cs == 0)
				    return;
				log_dbg(5, "RECVREC: %i SENDREC %i recvapp %i sendapp %i", (conn->ssl_state & BR_SSL_RECVREC), (conn->ssl_state & BR_SSL_SENDREC), (conn->ssl_state & BR_SSL_RECVAPP), (conn->ssl_state & BR_SSL_SENDAPP));
				if (conn->ssl_state == BR_SSL_CLOSED)
				    break;

				if ((conn->ssl_state & BR_SSL_SENDREC)) {
						//if ((sendrec++ == 0) && (conn->ev_w.filter == 0)) {
						//if ((sendrec++ == 0) && ((conn->ev.filter & EV_WRITE) == 0)) {
						if (sendrec++ == 0) {
							  log_dbg(5, "ADD SEND");
								EQ_ADD(thr->eq, &conn->ev, conn->fd, EV_WRITE, conn_write, conn, 0);
						}
			  }

				if ((conn->ssl_state & BR_SSL_RECVREC)) {
						//if ((recvrec++ == 0) && (conn->ev_r.filter == 0)) {
						//if ((recvrec++ == 0) && ((conn->ev.filter & EV_READ) == 0)) {
						if (recvrec++ == 0) {
						    log_dbg(5, "ADD RECV");
								EQ_ADD(thr->eq, &conn->ev, conn->fd, EV_READ, conn_read, conn, 0);
						}
				}

				// exit and wait for the events we set up previousy
        if ((sendrec > 1) || (recvrec > 1) || (conn->cs & CS_WAIT)) {
					  log_dbg(5, "EXIT");
					  return;
				}

//				if ((conn->ssl_state & BR_SSL_RECVAPP) && ((conn->status == SENDRECV) || (conn->status == RECV))) {
						if ((conn->ssl_state & BR_SSL_RECVAPP) && (conn->cs & CS_RECV)) {

				    log_dbg(5, "\n# RECVAPP----------- : conn->status: %x\n", conn->cs);
						// update timer
						conntab_update(conn);
log_dbg(5, "d");
						// recv app data
						app_recv(conn);
				}
//				if ((conn->ssl_state & BR_SSL_SENDAPP) && ((conn->status == SENDRECV) || (conn->status == SEND) || conn->status == ERROR)) {
				if ((conn->ssl_state & BR_SSL_SENDAPP) && ((conn->cs & CS_SEND) || (conn->cs & CS_CLOSE))) {

						log_dbg(5, "\n# SENDAPP----------- : conn->status: %x\n", conn->cs);

						// update timer
						conntab_update(conn);

						// send app data
						app_send(conn);
						log_dbg(5, "\nFGGGGGGGGG\n\n %i", conn->cs);
				}
	  }

		// error condition, log and termintate connection
		log_dbg(5, "SSL error: %d", br_ssl_engine_last_error(&conn->ssl_sc.eng));
		conntab_remove(conn);
}


// main http2 write function
int
http2_write(struct connect* conn, char** buf, int len)
{
		struct stream* strm;
		int w_len = 0;
		int rv = 0;
log_dbg(5, "GGG0 highest sid %i", conn->hs);

		// TODO: server settings/flow control
		// we need to send the server h2_preface first (server settings) already assigned during h2_init
		if (conn->h2_preface == 1) {

			  // check if the send buffer length is large enough for the header
				if ((w_len + H2_HEADER_SIZE + BUFFER_SIZE) > len)
				    return w_len;

				// create the server settings frame with our default values (NOT YET IMPLEMENTED)
			  construct_frame_header((uint8_t *)(*buf), 0, 0, SETTINGS, 0);

				// signal we're done and advance length
				conn->h2_preface = 0;
			  w_len += H2_HEADER_SIZE;
		}
log_dbg(5, "GGG");
		// we received the client settings frame, need to acknowledge it
		if ((conn->send_settings == 1) && (conn->h2_state == H2_IDLE)){

				// check if the send buffer length is large enough for the header
				if ((w_len + H2_HEADER_SIZE + BUFFER_SIZE) > len)
				    return w_len;

				// create settings ack frame - 0 payload - and add it to the total length to send
			  construct_frame_header((uint8_t *)(*buf + w_len), 0, 1, SETTINGS, 0);

				// signal we're done and advance length
			  conn->send_settings = 0;
				w_len += H2_HEADER_SIZE;
		}

		if (conn->send_ping == 1) {
			  // check if the send buffer length is large enough for the header
			  if ((w_len + H2_HEADER_SIZE + BUFFER_SIZE) > len)
					  return w_len;

				// create settings ack frame - 0 payload - and add it to the total length to send
				construct_frame_header((uint8_t *)(*buf + w_len), 8, 1, PING, 0);

				memcpy((uint8_t *)(*buf + w_len + 9), conn->ping_data, 8);
//				hp.data = buf + (sizeof(uint8_t) * (H2_HEADER_SIZE + 4));

				// signal we're done and advance length
				conn->send_ping = 0;
				w_len += (H2_HEADER_SIZE + 8);

				log_dbg(5, "PING ACK!!");
		}
log_dbg(5, "GGG");

		// loop through streams and process as needed
    for (struct stream* strm = conn->strm_head; strm != NULL; strm = strm->next) {
		    uint8_t flags = 0;
				int f_len = 0;
				enum h2_frame_type f_typ = 0;
				uint32_t h2_sid;
log_dbg(5, "NEW->> SID: %i ss: %i", strm->h2_sid, strm->ss);
				if ((w_len + H2_HEADER_SIZE + BUFFER_SIZE) > len)
				    return w_len;

				if ((strm->h2_err == STREAM_CLOSED) && (strm->T)) {  ///////////////////////////////
log_dbg(5, "OH NO");
//exit(0);
            strm->h2_ss = SS_HCLOSED_LOCAL;
					  construct_frame_header((uint8_t *)(*buf + w_len), 0, 0, RST_STREAM, strm->h2_sid);
					  strm_reset(strm);
					  w_len += (f_len + H2_HEADER_SIZE);
					  continue;
				}

				// check if the request is done and stream is not blocked; more on to the next strm otherwise
			  if ((strm->ss == SS_INIT) || (strm->ss & SS_RECV) || (strm->ss & SS_WAIT)) {
					  log_dbg(5, "GOTTA WAIT: strm->rd %i strm->status %i sid: %i", strm->rd, strm->ss, strm->h2_sid);
				    continue;
				}
log_dbg(5, "sid %i method: %i", strm->h2_sid, strm->http_method);

				// check if our buffer is large enough to write a "full" header frame
				if ((len - w_len) < (H2_HEADER_SIZE + BUFFER_SIZE))
				    return w_len;
log_dbg(5, "HEADHER HERADER STRM SS %i", strm->ss);
        if ((strm->ss == SS_HEAD) || ((strm->T == NULL) && (strm->ss == SS_HEAD))) {
//					  f_typ = HEADERS;
				    rv = http2_header(strm, *buf + w_len, len);
log_dbg(5, "WROTE HEAD NOT FOIND %i sid %i", rv, strm->h2_sid);
						if (rv <= 0)
						    return w_len;

						w_len += rv;

		    } else if (strm->ss == SS_ERROR) {
						 flags |= FF_END_HEADERS;
						 flags |= FF_END_STREAM;
						 strm->h2_ss = SS_HCLOSED_LOCAL;
						 construct_frame_header((uint8_t *)(*buf + w_len), 0, flags, HEADERS, strm->h2_sid);
						 strm_reset(strm);
						 return w_len;
				}

						if (strm->T == NULL) {
							  log_dbg(5, "NOT FOUND");
						    //f_len = snprintf(*buf + w_len + H2_HEADER_SIZE, 18, "%s", "<html>ffff</html>");
								f_len = snprintf(*buf + w_len + H2_HEADER_SIZE, strlen(HTTP_BODY_T) + 2, "%s", HTTP_BODY_T);
						} else
			          f_len = lev_write(strm, *buf + w_len + H2_HEADER_SIZE, MIN(conn->h2_set.max_frame_size, (len - w_len - H2_HEADER_SIZE)));

log_dbg(5, "YAYAYAYAY f_len: %i, lua_status: %i, strm->T: %p", f_len, strm->lua_status, strm->T);

		        if (f_len) {
								//exit(0);
							  h2_sid = strm->h2_sid;
			          //if (strm->T == NULL) {
								if (strm->lua_status != LUA_YIELD) {
									    log_dbg(5, "YAYAYAYAY2");
			                flags |= FF_END_STREAM;
							        strm->h2_ss = SS_HCLOSED_LOCAL;
											strm_reset(strm);
									}
log_dbg(5, "SID HERE %i", h2_sid);

			          construct_frame_header((uint8_t *)(*buf + w_len), f_len, flags, DATA, h2_sid);
			          w_len += (f_len + H2_HEADER_SIZE);

						    continue;
						// promise
					  } else if (strm->ss == SS_HEAD) {
	//				  	strm = strm->prev;
						    log_dbg(5, "GOT NO FLEN %i ss %i", strm->lua_status, strm->ss);
								//strm = h2_find_stream(strm->conn, conn->cdbg);
								//strm = strm->prev;
						    continue;
					}

						if (strm->lua_status != LUA_YIELD) {
							  construct_frame_header((uint8_t *)(*buf + w_len), 0, 0, RST_STREAM, strm->h2_sid);
							  strm_reset(strm);
							  w_len += H2_HEADER_SIZE;
						}

    }

		return w_len;

}

char *
status_msg(int code, int* len)
{
	  struct {
        int code;
        char *msg;
    } http_status[] = HTTP_STATUS;

		for (int i = 0; http_status[i].msg != NULL; i++) {
			  if (code == http_status[i].code) {
						*len = strlen(http_status[i].msg);
				    return http_status[i].msg;
				}
		}

	  return NULL;
}

int
http_error(struct stream* strm, char *buf, int len)
{
		const char* status;
		const char* body;

		char date[32];
		int wlen = 0;
		int slen = 0;
		int code;

		if (strm->T == NULL)
				code = (strm->ss == SS_ERROR) ? 400 : 404;
		else
				code = 500;

		status = status_msg(code, &slen);

		wlen = snprintf(buf, len, "%s %s\r\n", (strm->conn->protocol) ? strm->conn->protocol : "HTTP/1.0", status);

		wlen += snprintf((buf + wlen), MAX(0, (len - wlen)), "Software: %s\r\n", SOFTWARE_NAME);
		wlen += snprintf((buf + wlen), MAX(0, (len - wlen)), "Date: %s\r\n", httpd_time(date, sizeof date));
		wlen += snprintf((buf + wlen), MAX(0, (len - wlen)), "Content-Type: %s\r\n", "text/html; charset=UTF-8");
		wlen += snprintf((buf + wlen), MAX(0, (len - wlen)), "Content-Length: %d\r\n\r\n", strlen(HTTP_BODY_T) + 2 * (slen - 2));

		wlen += snprintf((buf + wlen), (len - wlen), HTTP_BODY_T, status, status);

		if (wlen >= len)
		    log_dbg(5, "write buffer too small, response trunkated");

		return wlen;
}


int
http_write(struct connect* conn, char* buf[], int len)
{
    struct stream* strm = conn->strm;
    char* rbuf;
    int rv = 0;

		if ((strm->ss == SS_HEAD) && (strm->T != NULL)) {
				rv = http_header(strm, *buf, len);
		}
log_dbg(5, "HEADER wrote %s\n%i", *buf, rv);
		if ((strm->ss == SS_ERROR) || (strm->T == NULL)) {
			  rv = http_error(strm, *buf, len);
		} else
        rv += lev_write(strm, *buf + rv, len - rv);

		if ((strm->lua_status != LUA_YIELD) && (strm->ss != SS_ERROR))
				strm_reset(strm);

		change_state(conn, strm->ss);
    return rv;
} //f

int
alpn_h2_init(struct connect* conn) {
	  char const* alpn;
		int rv;

	  alpn = br_ssl_engine_get_selected_protocol(&conn->ssl_sc.eng);
		if (alpn) {
        if (memcmp(proto_name, alpn, strlen(proto_name)) == 0)
						return (h2_init(conn));
			  else
				    log_dbg(5, "ALPN negotiation failure");
				return (0);
		}
		log_dbg(5, "ALPN extension not found");
		return 0;
}

void
app_recv(struct connect* conn)
{
	  unsigned char* buf;
		size_t len;
		ssize_t rv;

    buf = br_ssl_engine_recvapp_buf(&conn->ssl_sc.eng, &len);

    memcpy(conn->rbuf + conn->rlen, buf, len);
    conn->rlen += len;

		if (conn->http_protocol == HTTP2)
				rv = http2_read(conn, conn->rbuf, conn->rlen);
		else
				rv = http_read(conn, conn->rbuf, conn->rlen);

		if (rv > 0) {
				len = len - (conn->rlen - rv);
				conn->rlen = 0;
		} //else if (conn->rlen > BUFFER_SIZE)
		  //  conn->cs = CS_CLOSE; //log and terminate conn
		else if (conn->cs & CS_WAIT)
		    return;
log_dbg(5, "ACCEPTING: %i", len);
    br_ssl_engine_recvapp_ack(&conn->ssl_sc.eng, len);
} //f

void
app_send(struct connect* conn)
{
	  char *buf;
		size_t len;
	  ssize_t rv;

	  buf = br_ssl_engine_sendapp_buf(&conn->ssl_sc.eng, &len);

		if (len < BUFFER_SIZE)
		    return;
log_dbg(5, "T");
	  if (conn->http_protocol == HTTP2)
			  rv = http2_write(conn, &buf, len);
	  else
			  rv = http_write(conn, &buf, len);

				//log_dbg(5, "going to %i write: %s", rv, buf);
				log_dbg(6, "going to write %i", rv);

		if (rv < 0)
		    conn->cs = CS_ERROR; //log and terminate conn
	  else if (rv > 0) {
			  br_ssl_engine_sendapp_ack(&conn->ssl_sc.eng, rv);
			  br_ssl_engine_flush(&conn->ssl_sc.eng, 0);
	  }
} //f


/* resume connection based on stream status */
void
conn_resume(struct stream* strm)
{
    struct connect* conn = strm->conn;

		if (conn->http_protocol < HTTP2) {
				if (strm->lua_status == 0) {
					  conn->cs = CS_RECV;
						reset_headers(strm);
			  }
				change_state(conn, conn->strm->ss);
				log_dbg(5, "@@@change_state: conn->cs: %x", conn->cs);

		} else {

				if (strm->lua_status == 0) {
						strm->h2_err = STREAM_CLOSED;
						log_dbg(5, "\nGOING TO CLOSE HERE SOMEHOW\n");
				}

//				for(strm = conn->strm_head; strm != NULL; strm = strm->next) {
//						if (strm->status == SS_PWRITE) {
//							  log_dbg(5, "BUT PENDING WRITE");
//							  conn->status = SEND;
//				        break;
//						}
//				}
				 //change_state(conn, strm->ss);
				 conn->cs = 3;
		}
    log_dbg(5, "final state: %i", conn->cs);
		return conn_io(conn);
}



///////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////

void
conn_read(struct edata *ev)
{
	  struct connect* conn = ev->ctx;
		char* buf;
	  ssize_t rv;
	  size_t len;

		buf = br_ssl_engine_recvrec_buf(&conn->ssl_sc.eng, &len);
		log_dbg(5, "READING ON CONN %i", conn->fd);

		rv = recv(ev->fd, buf, len, 0);
		log_dbg(5, "READ %i", rv);
		log_dbg(5, "errno %s", strerror(errno));

		if (rv <= 0) {
			  if (rv == -1 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
					  return;
				log_dbg(5, "socket read error: %s", strerror(errno));
				conn->cs = CS_CLOSE;
		} else
		    br_ssl_engine_recvrec_ack(&conn->ssl_sc.eng, rv);
log_dbg(5, "read DONE");
	  EQ_DEL(conn->thr->eq, &conn->ev, ev->fd, EV_READ);
		return (conn_io(conn));
}

void
//conn_write(int fd, void* ctx)
conn_write(struct edata *ev)
{
    struct connect* conn = ev->ctx;
    char* buf;
		ssize_t rv;
    size_t len;

    buf = br_ssl_engine_sendrec_buf(&conn->ssl_sc.eng, &len);
		log_dbg(5, "WRITNG ON CONN %i", conn->fd);

    rv = write(ev->fd, buf, len);

		if (rv <= 0) {
			  if (rv == -1 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
					  return;
				log_dbg(5, "socket write error: %s", strerror(errno));
				conn->cs = CS_ERROR;
		} else {
				br_ssl_engine_sendrec_ack(&conn->ssl_sc.eng, rv);
				log_dbg(5, "WROTE: %i total to write: %i", rv, len);
				if (rv < len)
	          return;
		}
log_dbg(5, "write DONE");
    EQ_DEL(conn->thr->eq, &conn->ev, ev->fd, EV_WRITE);
    return (conn_io(conn));
}
