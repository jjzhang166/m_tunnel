/* 
 * Copyright (c) 2015 lalawue
 * 
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the MIT license. See LICENSE for details.
 */

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#pragma comment(lib, "ws2_32.lib")

#else

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
/* #include <netinet/in.h> */
#include <net/if.h>
//#include <net/if_arp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/select.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <ctype.h>

#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "plat_type.h"
#include "plat_net.h"
#include "m_mem.h"
#include "m_debug.h"
#include <assert.h>

#define _err(...) _mlog("mnet", D_ERROR, __VA_ARGS__)
//#define _log(...) _mlog("mnet", D_VERBOSE, __VA_ARGS__)
#define _log(...)

#define _MIN_OF(a, b) (((a) < (b)) ? (a) : (b))
#define _MAX_OF(a, b) (((a) > (b)) ? (a) : (b))

#ifdef _WIN32
#define close(a) closesocket(a)
#define getsockopt(a,b,c,d,e) getsockopt((a),(b),(c),(char*)(d),(e))
#define setsockopt(a,b,c,d,e) setsockopt((a),(b),(c),(char*)(d),(e))
#define recv(a,b,c,d) recv((SOCKET)a,(char*)b,c,d)
#define send(a,b,c,d) send((SOCKET)a,(char*)b,c,d)
#define recvfrom(a,b,c,d,e,f) recvfrom((SOCKET)a,(char*)b,c,d,e,f)
#define sendto(a,b,c,d,e,f) sendto((SOCKET)a,(char*)b,c,d,e,f)

#undef  errno
#define errno WSAGetLastError()

#undef  EWOULDBLOCK
#define EWOULDBLOCK WSAEWOULDBLOCK
#define EINPROGRESS WSAEINPROGRESS

#endif  /* _WIN32 */

enum {
   MNET_SET_READ,
   MNET_SET_WRITE,
   MNET_SET_ERROR,
   MNET_SET_MAX,
};

typedef struct s_rwbuf {
   int ptr, ptw;
   struct s_rwbuf *next;
   char *buf;
} rwb_t;

typedef struct s_rwbuf_head {
   rwb_t *head;
   rwb_t *tail;
   int count;
} rwb_head_t;

struct s_mchann {
   int fd;
   void *opaque;
   chann_state_t state;
   chann_type_t type;
   chann_cb cb;
   struct sockaddr_in addr;
   socklen_t addr_len;
   rwb_head_t rwb_send;         /* fifo */
   struct s_mchann *prev;
   struct s_mchann *next;
   int64_t bytes_send;
   int64_t bytes_recv;
   int active_send_event;
};

typedef struct s_mnet {
   int init;
   int chann_count;
   chann_t *channs;
   struct timeval tv;
   fd_set fdset[MNET_SET_MAX];
} mnet_t;

static mnet_t g_mnet;

static inline mnet_t*
_gmnet() {
   return &g_mnet;
}

/* buf op
 */
static inline int
_rwb_count(rwb_head_t *h) { return h->count; }

static inline int
_rwb_buffered(rwb_t *b) {
   return b ? (b->ptw - b->ptr) : 0;
}

static inline int
_rwb_available(rwb_t *b) {
   return b ? (MNET_BUF_SIZE - b->ptw) : 0;
}

static inline rwb_t*
_rwb_new(void) {
   rwb_t *b = (rwb_t*)mm_malloc(sizeof(rwb_t) + MNET_BUF_SIZE);
   b->buf = (char*)b + sizeof(*b);
   return b;
}

static rwb_t*
_rwb_create_tail(rwb_head_t *h) {
   if (h->count <= 0) {
      h->head = h->tail = _rwb_new();
      h->count++;
   }
   else if (_rwb_available(h->tail) <= 0) {
      h->tail->next = _rwb_new();
      h->tail = h->tail->next;
      h->count++;
   }
   return h->tail;
}

static void
_rwb_destroy_head(rwb_head_t *h) {
   if (_rwb_buffered(h->head) <= 0) {
      rwb_t *b = h->head;
      h->head = b->next;
      mm_free(b);
      if ((--h->count) <= 0) {
         h->head = h->tail = 0;
      }
   }
}

static void
_rwb_cache(rwb_head_t *h, char *buf, int buf_len) {
   int buf_ptw = 0;
   while (buf_ptw < buf_len) {
      rwb_t *b = _rwb_create_tail(h);
      int len = _MIN_OF(buf_len - buf_ptw, _rwb_available(b));
      memcpy(&b->buf[b->ptw], &buf[buf_ptw], len);
      b->ptw += len;
      buf_ptw += len;
   }
}

static char*
_rwb_drain_param(rwb_head_t *h, int *len) {
   rwb_t *b = h->head;
   assert(b);
   *len = _rwb_buffered(b);
   return &b->buf[b->ptr];
}

static void
_rwb_drain(rwb_head_t *h, int drain_len) {
   while ((h->count>0) && (drain_len>0)) {
      rwb_t *b = h->head;
      int len = _MIN_OF(drain_len, _rwb_buffered(b));
      drain_len -= len;
      b->ptr += len;
      _rwb_destroy_head(h);
   }
}

static void
_rwb_destroy(rwb_head_t *h) {
   while (h->count > 0) {
      rwb_t *b = h->head;
      if ( b ) {
         h->head = b->next;
         h->count--;
         mm_free(b);
      }
   }
}

/* socket param op
 */
static int
_set_nonblocking(int fd) {
#ifdef _WIN32
   u_long imode = 1;
   int ret = ioctlsocket(fd, FIONBIO, (u_long*)&imode);
   if (ret == NO_ERROR) return 0;
#else
   int flag = fcntl(fd, F_GETFL, 0);
   if (flag != -1) return fcntl(fd, F_SETFL, flag | O_NONBLOCK);
#endif
   return -1;
}

static int
_set_broadcast(int fd) {
   int opt = 1;
   return setsockopt(fd, SOL_SOCKET, SO_BROADCAST, (char*)&opt, sizeof(opt));
}

static int
_set_keepalive(int fd) {
   int opt = 1;
   return setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (char*)&opt, sizeof(opt));
}

static int
_set_reuseaddr(int fd) {
   int opt = 1;
   return setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));
}

static int
_set_bufsize(int fd) {
   int len = MNET_BUF_SIZE;
   return (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (char*)&len, sizeof(len)) |
           setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (char*)&len, sizeof(len)));
}

static int
_bind(int fd, struct sockaddr_in *si) {
   return bind(fd, (struct sockaddr*)si, sizeof(*si));
}

static int
_listen(int fd, int backlog) {
   return listen(fd, backlog > 0 ? backlog : 3);
}

/* select op
 */
static void
_select_add(mnet_t *ss, int fd, int set) {
   FD_SET(fd, &ss->fdset[set]);
}

#if 0
static void
_select_del(mnet_t *ss, int fd, int set) {
   FD_CLR(fd, &ss->fdset[set]);
}
#endif

static int
_select_isset(fd_set *set, int fd) {
   return FD_ISSET(fd, set);
}

static void
_select_zero(mnet_t *ss, int set) {
   FD_ZERO(&ss->fdset[set]);
}

/* channel op
 */
static chann_t*
_chann_create(mnet_t *ss, chann_type_t type, chann_state_t state) {
   chann_t *n = (chann_t*)mm_malloc(sizeof(*n));
   n->state = state;
   n->type = type;
   n->next = ss->channs;
   if (ss->channs) {
      ss->channs->prev = n;
   }
   ss->channs = n;
   ss->chann_count++;
   _log("chann create %p, type:%d, count %d\n", n, type, ss->chann_count);
   return n;
}

static void
_chann_destroy(mnet_t *ss, chann_t *n) {
   if (n->next) n->next->prev = n->prev;
   if (n->prev) n->prev->next = n->next;
   else ss->channs = n->next;
   _rwb_destroy(&n->rwb_send);
   mm_free(n);
   ss->chann_count--;
   _log("chann destroy %p, count %d\n", n, ss->chann_count);
}

static chann_t*
_chann_accept(mnet_t *ss, chann_t *n) {
   struct sockaddr_in addr;
   socklen_t addr_len = sizeof(addr);
   int fd = accept(n->fd, (struct sockaddr*)&addr, &addr_len);
   if (fd > 0) {
      if (_set_nonblocking(fd) >= 0) {
         chann_t *c = _chann_create(ss, n->type, CHANN_STATE_CONNECTED);
         c->fd = fd;
         c->addr = addr;
         c->addr_len = addr_len;
         _log("chann %p accept %p fd %d, from %s, count %d\n", n, c, c->fd, mnet_chann_addr(c), ss->chann_count);
         return c;
      }
   }
   return NULL;
}

static void
_chann_close(mnet_t *ss, chann_t *n) {
   close(n->fd);
   n->state = CHANN_STATE_CLOSED;
   /* _log("chann close fd %d\n", n->fd); */
}

static void
_chann_event(chann_t *n, mnet_event_type_t event, chann_t *r) {
   chann_event_t e;
   e.event = event;
   e.n = n;
   e.r = r;
   e.opaque = n->opaque;
   if ( n->cb ) {
      n->cb( &e );
   }
}

/* mnet api
 */
int
mnet_init() {
   mnet_t *ss = _gmnet();
   if ( !ss->init ) {
#ifdef _WIN32
      WSADATA wdata;
      if (WSAStartup(MAKEWORD(2,2), &wdata) != 0) {
         _err("fail to init !\n");
         return 0;
      }
#else
      signal(SIGPIPE, SIG_IGN);
#endif
      memset(ss, 0, sizeof(mnet_t));
      ss->init = 1;
      _log("init\n");
      return 1;
   }
   return 0;
}

void
mnet_fini() {
   mnet_t *ss = _gmnet();
   if ( ss->init ) {
      chann_t *n = ss->channs;
      while ( n ) {
         chann_t *next = n->next;
         _chann_event(n, MNET_EVENT_CLOSE, NULL);
         _chann_close(ss, n);
         _chann_destroy(ss, n);
         n = next;
      }
#ifdef _WIN32
      WSACleanup();
#endif
      ss->init = 0;
      _log("fini\n");
   }
}

int mnet_report(int level) {
   mnet_t *ss = _gmnet();
   if (ss->init) {
      if (level > 0){
         _log("-------- channs --------\n");
         chann_t *n = ss->channs, *nn = NULL;
         while (n) {
            nn = n->next;
            _log("chann %p, %s:%d\n", n, mnet_chann_addr(n), mnet_chann_port(n));
            n = nn;
         }
         _log("------------------------\n");
      }
      return ss->chann_count;
   }
   return -1;
}

chann_t*
mnet_chann_open(chann_type_t type) {
   return _chann_create(_gmnet(), type, CHANN_STATE_CLOSED);
}

void mnet_chann_close(chann_t *n) {
   if ( n ) {
      if (n->state == CHANN_STATE_CLOSING) {
         _chann_close(_gmnet(), n);
         _chann_destroy(_gmnet(), n);
      } else {
         n->state = CHANN_STATE_CLOSING;
      }
   }
}

int mnet_chann_state(chann_t *n) {
   return n ? n->state : CHANN_STATE_CLOSED;
}

static void
_chann_fill_addr(chann_t *n, const char *host, int port) {
   n->addr.sin_family = AF_INET;
   n->addr.sin_port = htons(port);
   n->addr.sin_addr.s_addr = 
      host==NULL ? htonl(INADDR_ANY) : inet_addr(host);
   n->addr_len = sizeof(n->addr);
}

static int
_chann_open_socket(chann_t *n, const char *host, int port, int backlog) {
   if (n->state == CHANN_STATE_CLOSED) {
      int istcp = n->type == CHANN_TYPE_STREAM;
      int isbc = n->type == CHANN_TYPE_BROADCAST;
      int fd = socket(AF_INET, istcp ? SOCK_STREAM : SOCK_DGRAM, 0);
      if (fd > 0) {
         _chann_fill_addr(n, host, port);

         if (_set_reuseaddr(fd) < 0) goto fail;
         if (backlog && _bind(fd, &n->addr) < 0) goto fail;
         if (backlog && istcp && _listen(fd,backlog) < 0) goto fail;
         if (_set_nonblocking(fd) < 0) goto fail;
         if (istcp && _set_keepalive(fd)<0) goto fail;
         if (isbc && _set_broadcast(fd)<0) goto fail;
         if (_set_bufsize(fd) < 0) goto fail;
         return fd;

        fail:
         close(fd);
         perror("chann open socket: ");
      }
   }
   else if (n->type==CHANN_TYPE_DGRAM || n->type==CHANN_TYPE_BROADCAST) {
      return n->fd;
   }
   return -1;
}

int
mnet_chann_connect(chann_t *n, const char *host, int port) {
   if (n && host && port>0) {
      int fd = _chann_open_socket(n, host, port, 0);
      if (fd > 0) {
         n->fd = fd;
         if (n->type == CHANN_TYPE_STREAM) {
            int r = connect(fd, (struct sockaddr*)&n->addr, n->addr_len);
            if (r < 0) {
               if (errno==EINPROGRESS || errno==EWOULDBLOCK)
                  n->state = CHANN_STATE_CONNECTING;
            }
            _log("chann %p fd:%d type:%d connecting...\n", n, fd, n->type);
         } else {
            n->state = CHANN_STATE_CONNECTED;
            _log("chann %p fd:%d type:%d connected\n", n, fd, n->type);
         }
         return 1;
      }
      _err("chann %p fail to connect\n", n);
   }
   return 0;
}

int
mnet_chann_listen_ex(
   chann_t *n, const char *host, int port, int backlog) {
   if (n && port>0) {
      int fd = _chann_open_socket(n, host, port, backlog | 1);
      if (fd > 0) {
         n->fd = fd;
         n->state = CHANN_STATE_LISTENING;
         _log("chann %p, fd:%d listen\n", n, fd);
         return 1;
      }
      _err("chann %p fail to listen\n", n);
   }
   return 0;
}

/* mnet channel api
 */
void mnet_chann_set_cb(chann_t *n, chann_cb cb, void *opaque) {
   if ( n ) {
      n->cb = cb;
      n->opaque = opaque;
   }
}

void mnet_chann_active_event(chann_t *n, mnet_event_type_t et, int active) {
   if ( n ) {
      if (et == MNET_EVENT_SEND) {
         n->active_send_event = active;
      }
   }
}

int mnet_chann_recv(chann_t *n, void *buf, int len) {
   if (n && buf && len>0) {
      int ret = 0;
      if (n->type == CHANN_TYPE_STREAM) {
         ret = (int)recv(n->fd, buf, len, 0);
      } else {
         n->addr_len = sizeof(n->addr);
         ret = (int)recvfrom(n->fd, buf, len, 0, (struct sockaddr*)&(n->addr), &(n->addr_len));
      }
      if (ret <= 0) {
         if (errno != EWOULDBLOCK) {
            n->state = CHANN_STATE_CLOSING;
         }
      } else {
         n->bytes_recv += ret;
      }
      return ret;
   }
   assert(n);
   return -1;
}

static int
_chann_send(chann_t *n, void *buf, int len) {
   int ret = 0;
   if (n->type == CHANN_TYPE_STREAM) {
      ret = (int)send(n->fd, buf, len, 0);
   } else {
      ret = (int)sendto(n->fd, buf, len, 0, (struct sockaddr*)&n->addr, n->addr_len);
   }
   if (ret > 0) {
      n->bytes_send += ret;
   }
   return ret;
}

int mnet_chann_send(chann_t *n, void *buf, int len) {
   if ( n ) {
      int ret = len;
      rwb_head_t *prh = &n->rwb_send;

      if (_rwb_count(prh) > 0) {
         _rwb_cache(prh, buf, len);
      }
      else {
         ret = _chann_send(n, buf, len);
         if (ret <= 0) {
            if (errno != EWOULDBLOCK) {
               /* perror("chann send: "); */
               n->state = CHANN_STATE_CLOSING;
            }
         } else if (ret < len) {
            _rwb_cache(prh, ((char*)buf) + ret, len - ret);
            printf("------------ cache %d of %d!\n", ret, len);
            ret = len;
         }
      }
      return ret;
   }
   assert(n);
   return -1;
}

int mnet_chann_cached(chann_t *n) {
   rwb_head_t *prh = &n->rwb_send;
   if (n && _rwb_count(prh) > 0) {
      rwb_t *b = prh->head;
      int i = 0, bytes = 0;
      for (i=0; i<_rwb_count(prh); i++) {
         bytes += _rwb_buffered(b);
         b = b->next;
      }
      return bytes;
   }
   return 0;
}

char* mnet_chann_addr(chann_t *n) {
   if ( n ) {
      return inet_ntoa(n->addr.sin_addr);
   }
   return NULL;
}

int mnet_chann_port(chann_t *n) {
   if (n) {
      return ntohs(n->addr.sin_port);
   }
   return 0;
}

long long mnet_chann_bytes(chann_t *n, int be_send) {
   if ( n ) {
      return (be_send ? n->bytes_send : n->bytes_recv);
   }
   return -1;
}

int
mnet_check(int microseconds) {
   int nfds = 0;
   chann_t *n = NULL;
   mnet_t *ss = _gmnet();
   fd_set *sr, *sw, *se;

   nfds = 0;

   _select_zero(ss, MNET_SET_READ);
   _select_zero(ss, MNET_SET_WRITE);
   _select_zero(ss, MNET_SET_ERROR);

   n = ss->channs;
   while ( n ) {
      switch (n->state) {
         case CHANN_STATE_LISTENING:
         case CHANN_STATE_CONNECTED:
            nfds = nfds<=n->fd ? n->fd+1 : nfds;
            _select_add(ss, n->fd, MNET_SET_READ);
            if ((_rwb_count(&n->rwb_send)>0) || n->active_send_event) {
               _select_add(ss, n->fd, MNET_SET_WRITE);
            }
            break;
         case CHANN_STATE_CONNECTING:
            nfds = nfds<=n->fd ? n->fd+1 : nfds;
            _select_add(ss, n->fd, MNET_SET_WRITE);
            _select_add(ss, n->fd, MNET_SET_ERROR);
            break;
         default:
            break;
      }
      n = n->next;
   }

   sr = &ss->fdset[MNET_SET_READ];
   sw = &ss->fdset[MNET_SET_WRITE];
   se = &ss->fdset[MNET_SET_ERROR];

   ss->tv.tv_sec = 0;
   ss->tv.tv_usec = microseconds;
   if (select(nfds, sr, sw, se, microseconds >= 0 ? &ss->tv : NULL) < 0) {
      if (errno != EINTR) {
         perror("select error !\n");
         abort();
         return -1;
      }
   }

   n = ss->channs;
   while ( n ) {
      chann_t *nn = n->next;
      switch ( n->state ) {
         case CHANN_STATE_LISTENING:
            if ( _select_isset(sr, n->fd) ) {
               if (n->type == CHANN_TYPE_STREAM) {
                  chann_t *c = _chann_accept(ss, n);
                  if (c) _chann_event(n, MNET_EVENT_ACCEPT, c);
               } else {
                  _chann_event(n, MNET_EVENT_RECV, NULL);
               }
            }
            break;

         case CHANN_STATE_CONNECTING:
            if ( _select_isset(sw, n->fd) ) {
               int opt=0; socklen_t opt_len=sizeof(opt);
               getsockopt(n->fd, SOL_SOCKET, SO_ERROR, &opt, &opt_len);
               if (opt == 0) {
                  n->state = CHANN_STATE_CONNECTED;
                  _chann_event(n, MNET_EVENT_CONNECT, NULL);
               } else {
                  n->state = CHANN_STATE_CLOSING;
                  _chann_event(n, MNET_EVENT_DISCONNECT, NULL);
               }
            }
            if ( _select_isset(se, n->fd) ) {
               n->state = CHANN_STATE_CLOSING;
               _chann_event(n, MNET_EVENT_DISCONNECT, NULL);
            }
            break;

         case CHANN_STATE_CONNECTED:
            if ( _select_isset(sr, n->fd) ) {
               _chann_event(n, MNET_EVENT_RECV, NULL);
            }
            if ( _select_isset(sw, n->fd) ) {
               rwb_head_t *prh = &n->rwb_send;
               if (_rwb_count(prh) > 0) {
                  int ret=0, len=0;
                  char *buf = _rwb_drain_param(prh, &len);
                  ret = _chann_send(n, buf, len);
                  if (ret > 0) _rwb_drain(prh, ret);
               }
               else if ( n->active_send_event ) {
                  _chann_event(n, MNET_EVENT_SEND, NULL);
               }
            }
            break;
         default:
            break;
      }
      if (n->state == CHANN_STATE_CLOSING) {
         _chann_event(n, MNET_EVENT_CLOSE, NULL);
         _chann_close(ss, n);
         _chann_destroy(ss, n);
      }
      n = nn;
   }
   return ss->chann_count;
}
