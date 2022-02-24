/* some http protocol specifics */

#ifndef _HTTP_H_
#define _HTTP_H_ 1

#define HTTP_STATUS		{			\
	{ 100,	"100 Continue" },				\
	{ 400,	"400 Bad Request" },		\
	{ 404,	"404 Not Found" },				\
  { 500,	"500 Server Error" },        \
  { 0,		NULL}       \
}

static const char *HTTP_BODY_T = "<!DOCTYPE html>\n<html>\n<head>\n<meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\"/>\n<title>%s</title>\n</head><body><h1>%s</h1><hr></body></html>";

#define HTTP_PROTOCOLS {"HTTP/1.0", "HTTP/1.1", "HTTP/2", NULL}
#define TXT_HTTP11 "HTTP/1.1"
#define TXT_HTTP2 "HTTP/2"
#define CLIENT_MAGIC "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
#define CLIENT_MAGIC_LEN 24

/*
static const char *HTTP1_X_HEAD = "\
%.80s\r\n\
Content-Type: text/html\r\n\
Server: lhttpd\r\n";
*/

/*
#define MEDIA_TYPES		{			\
	{ "%s",	"%s" },	\
	{ "Content-Type: ",	"text/html" },	\
	{ "Server",  "plain" },	\
	{ "gif", "gif" },	\
	{ "jpeg",	"jpeg" },	\
	{ "jpg", "jpeg" },	\
	{ "png", "png" },	\
	{ "js",		"application",	"javascript" },	\
	{ NULL }					\
}
*/

//static const char *HTTP_BODY = "<!DOCTYPE html>\n<html>\n<head>\n<meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\"/>\n<title>%s</title>\n</head><body><h1>%s</h1><hr></body></html>";
//static const char *HTTP404 = "<!DOCTYPE html>\n<html>\n<head>\n<meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\"/>\n<title>404 Not Found</title>\n</head><body><h1>404 Not Found</h1><hr></body></html>";

enum http_protocol {UNSUPPORTED_PROTOCOL = 0, HTTP10, HTTP11, HTTP2};
enum http_scheme {HTTP, HTTPS};

#define HTTP_METHODS {"GET", "POST", "HEAD", NULL}
enum http_method {UNSUPPORTED_METHOD = 0, PRI, GET, HEAD, CONNECT, DELETE, OPTIONS, PATCH, POST, PUT, TRACE};

// HTTP/2 state
enum h2_state {H2_WAITING_MAGIC = 0, H2_WAITING_SETTINGS, H2_IDLE, H2_GOAWAY, H2_BLINDED};

// HTTP/2 stream states
enum h2_stream_state {SS_IDLE = 0, SS_RESERVED_LOCAL, SS_RESERVED_REMOTE, SS_OPEN, SS_HCLOSED_LOCAL, SS_HCLOSED_REMOTE, SS_CLOSED}; //f

enum SETTINGS_ID {
    H2_SETTINGS_HEADER_TABLE_SIZE = 0x01,
    H2_SETTINGS_ENABLE_PUSH = 0x02,
    H2_SETTINGS_MAX_CONCURRENT_STREAMS = 0x03,
    H2_SETTINGS_INITIAL_WINDOW_SIZE = 0x04,
    H2_SETTINGS_MAX_FRAME_SIZE = 0x05,
    H2_SETTINGS_MAX_HEADER_LIST_SIZE = 0x06,
    H2_SETTINGS_ENABLE_CONNECT_PROTOCOL = 0x08
};

// HTTP/2 frame types
enum h2_frame_type {
	  DATA = (0x0),
    HEADERS = (0x1),
    PRIORITY = (0x2),
    RST_STREAM = (0x3),
    SETTINGS = (0x4),
    PUSH_PROMISE = (0x5),
    PING = (0x6),
    GOAWAY = (0x7),
    WINDOW_UPDATE = (0x8),
    CONTINUATION = (0x9)
}; //f

enum h2_frame_flags {
	  FF_END_STREAM = (0x1),
    FF_END_HEADERS = (0x4),
    FF_PADDED = (0x8),
    FF_PRIORITY = (0x20)
};

enum h2_error_codes {
	  NO_ERROR = (0x0),
    PROTOCOL_ERROR = (0x1),
    INTERNAL_ERROR = (0x2),
    FLOW_CONTROL_ERROR = (0x3),
    SETTINGS_TIMEOUT = (0x4),
    STREAM_CLOSED = (0x5),
    FRAME_SIZE_ERROR = (0x6),
    REFUSED_STREAM = (0x7),
    CANCEL = (0x8),
    COMPRESSION_ERROR = (0x9),
    CONNECT_ERROR = (0xa),
    ENHANCE_YOUR_CALM = (0xb),
    INADEQUATE_SECURITY = (0xc),
    HTTP_1_1_REQUIRED = (0xd)
}; //f

static struct content_type {
	  const char* ext;
	  const char* type;
} content_type[] = {
	  { ".css",	"text/css" },
	  { ".html",	"text/html" },
	  { ".txt",	"text/plain" },
	  { ".gif",	"image/gif" },
	  { ".jpeg",	"image/jpeg" },
	  { ".jpg",	"image/jpeg" },
	  { ".png",	"image/png" },
	  { ".svg",	"image/svg+xml" },
	  { ".js",		"application/javascript" },
		{ NULL,		"application/octet-stream" }
};

static struct http_code {
	  const int code;
		const char* desc;
} http_code[] = {
	  { 200, "OK" },
		{ 500, "Server Error" }
};

//char* dHTTP_404 = "ml";

//const char * const errrrr404 = "";
//char* HTTP_404 = "<!DOCTYPE html>\n<html>\n<head>\n<meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\"/>\n<title>404 Not Found</title>\n</head><body><h1>404 Not Found</h1><hr></body></html>";

//char* err500 = "";

struct header_field {
		char* hf_key;
		char* hf_val;
		struct header_field* hf_next;
};

struct header {
		char* key;
		char* val;
		struct header* next;
};

#endif
