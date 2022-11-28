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

#ifndef _HTTP_H_
#define _HTTP_H_ 1

/* some http protocol specifics */

#define HTTP_STATUS    {      \
  { 100,  "100 Continue" },        \
  { 400,  "400 Bad Request" },    \
  { 404,  "404 Not Found" },        \
  { 500,  "500 Server Error" },        \
  { 0,    NULL}       \
}

static const char *HTTP_BODY_T = "<!DOCTYPE html>\n<html>\n<head>\n<meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\"/>\n<title>%s</title>\n</head><body><h1>%s</h1><hr></body></html>";

#define HTTP_PROTOCOLS {"UNKNOWN", "HTTP/1.0", "HTTP/1.1", "HTTP/2"}
#define CLIENT_MAGIC "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
#define CLIENT_MAGIC_LEN 24

enum http_protocol {UNKNOWN_PROTOCOL = 0, HTTP10, HTTP11, HTTP2};
enum http_scheme {HTTP, HTTPS};

enum http_method {UNKNOWN_METHOD = 0, PRI, GET, HEAD, CONNECT, DELETE, OPTIONS, PATCH, POST, PUT, TRACE};

// HTTP/2 state
enum h2_state {H2_WAITING_MAGIC = 0, H2_WAITING_SETTINGS, H2_IDLE, H2_GOAWAY};

// HTTP/2 stream states
enum h2_stream_state {SS_IDLE = 0, SS_RESERVED_LOCAL, SS_RESERVED_REMOTE, SS_OPEN, SS_HCLOSED_LOCAL, SS_HCLOSED_REMOTE, SS_CLOSED};

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
};

enum h2_frame_flags {
    FF_END_STREAM = (0x1),
    FF_END_HEADERS = (0x4),
    FF_PADDED = (0x8),
    FF_PRIORITY = (0x20)
};

enum h2_error {
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
};

#endif
