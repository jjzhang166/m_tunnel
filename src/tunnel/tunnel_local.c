/* 
 * Copyright (c) 2015 lalawue
 * 
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the MIT license. See LICENSE for details.
 */

#define _BSD_SOURCE             /* for daemon */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <signal.h>

#include "m_mem.h"
#include "m_buf.h"
#include "m_list.h"
#include "m_debug.h"

#include "plat_type.h"
#include "plat_net.h"
#include "plat_time.h"

#include "utils_str.h"
#include "utils_conf.h"
#include "utils_misc.h"

#include "tunnel_cmd.h"
#include "tunnel_dns.h"
#include "tunnel_local.h"

#include <assert.h>

#define _err(...) _mlog("local", D_ERROR, __VA_ARGS__)
#define _info(...) _mlog("local", D_INFO, __VA_ARGS__)
#define _verbose(...) _mlog("local", D_VERBOSE, __VA_ARGS__)

#ifdef TEST_TUNNEL_LOCAL

#define TUN_LOCAL_DNS_FILE_NAME "data/local_records.txt"
#define TUN_LOCAL_BLOCK_FILE_NAME "data/local_blocks.txt"

/* for mode standalone */
typedef enum {
   LOCAL_CHANN_STATE_NONE = 0,       /* init state */
   LOCAL_CHANN_STATE_WAIT_LOCAL,     /* opened, need to recieve '05 01 00' */
   LOCAL_CHANN_STATE_ACCEPT,         /* connected local, send '05 00' */
   LOCAL_CHANN_STATE_DISCONNECT,     /* disconnect from remote, no need to send close */
   LOCAL_CHANN_STATE_WAIT_REMOTE,    /* wait remote connected */
   LOCAL_CHANN_STATE_CONNECTED,      /* remote connected */
} local_chann_state_t;

typedef struct {
   local_chann_state_t state;
   int chann_id;                /* for mode front */
   chann_t *tcpin;              /* for input */
   chann_t *tcpout;             /* for mode standalone */
   buf_t *bufin;                /* buf for input */
   buf_t *bufout;               /* for mode standalone */
   lst_node_t *node;            /* node in active_list */
   char query_domain[TUNNEL_DNS_DOMAIN_LEN];
} tun_local_chann_t;

typedef struct {
   int running;                 /* running status */
   int timer_active;
   int data_mark;
   int chann_idx;
   tunnel_local_mode_t mode;
   tunnel_local_config_t conf;
   chann_t *tcpin;              /* tcp for listen */
   chann_t *tcpout;             /* tcp for forward */
   buf_t *bufout;               /* buf for forward */
   lst_t *active_lst;           /* active chann list */
   lst_t *free_lst;             /* free chann list */
   tun_local_chann_t *channs[TUNNEL_CHANN_MAX_COUNT];
} tun_local_t;

static tun_local_t _g_local;

static void _tun_local_chann_tcpin_cb_standalone(chann_event_t *e);
static void _tun_local_chann_tcpout_cb_standalone(chann_event_t *e);

static inline tun_local_t* _tun_local(void) {
   return &_g_local;
}

/* description: chann r from local listen
 */
static void
_tun_local_chann_open(chann_t *r) {
   tun_local_t *tun = _tun_local();
   tun_local_chann_t *c = NULL;
   if (lst_count(tun->free_lst) > 0) {
      c = lst_popf(tun->free_lst);
   }
   else {
      c = (tun_local_chann_t*)mm_malloc(sizeof(*c));
      c->bufin = buf_create(TUNNEL_CHANN_BUF_SIZE);
      if (tun->mode == TUNNEL_LOCAL_MODE_STANDALONE) {
         c->bufout = buf_create(TUNNEL_CHANN_BUF_SIZE);
      }
      c->chann_id = tun->chann_idx;
      tun->chann_idx += 1;
   }
   tun->channs[c->chann_id] = c;
   c->tcpin = r;
   c->tcpout = NULL;
   c->node = lst_pushl(tun->active_lst ,c);

   if (tun->mode == TUNNEL_LOCAL_MODE_STANDALONE) {
      c->state = LOCAL_CHANN_STATE_NONE;
      mnet_chann_set_cb(c->tcpin, _tun_local_chann_tcpin_cb_standalone, c);
   }

   //_verbose("chann %d open, [a:%d,f:%d]\n", c->chann_id,
   //         lst_count(tun->active_lst), lst_count(tun->free_lst));
}

/* description: only shut down mnet socket, but keep local active */
static void
_tun_local_chann_disable(tun_local_chann_t *c) {
   c->state = LOCAL_CHANN_STATE_WAIT_REMOTE;

   mnet_chann_set_cb(c->tcpin, NULL, NULL);
   mnet_chann_set_cb(c->tcpout, NULL, NULL);

   if (mnet_chann_state(c->tcpin) >= CHANN_STATE_CONNECTING) {
      mnet_chann_close(c->tcpin);
   }
   if (mnet_chann_state(c->tcpout) >= CHANN_STATE_CONNECTING) {
      mnet_chann_close(c->tcpout);
   }

   //_verbose("chann %d disable\n", c->chann_id);
}

/* description: free local resources
 */
static void
_tun_local_chann_close(tun_local_chann_t *c) {
   tun_local_t *tun = _tun_local();
   if (c->node) {
      c->state = LOCAL_CHANN_STATE_NONE;

      lst_remove(tun->active_lst, c->node);
      lst_pushl(tun->free_lst, c);

      c->node = NULL;
      tun->channs[c->chann_id] = NULL;

      //_verbose("chann %d close, (a:%d,f:%d)\n", c->chann_id,
      //         lst_count(tun->active_lst), lst_count(tun->free_lst));
   }
}

/* description: open tcpout when tcpin request connect to addr
 */
static int
_tun_local_chann_tcpout_create(tun_local_chann_t *c, char *addr, int port) {
   c->tcpout = mnet_chann_open(CHANN_TYPE_STREAM);
   mnet_chann_set_cb(c->tcpout, _tun_local_chann_tcpout_cb_standalone, c);
   if (mnet_chann_connect(c->tcpout, addr, port) > 0) {
      //_verbose("tcpout create (%s:%d), %p(%p)\n", addr, port, c, c->tcpout);      
      return 1;
   }
   _err("tcpout fail to create (%s:%d)\n", addr, port);
   return 0;   
}

static int
_hex_equal(uint8_t *s, int slen, uint8_t *e, int elen) {
   int mlen = _MIN_OF(slen, elen);

   for (int i=0; i<mlen; i++) {
      if (s[i] != e[i]) {
         return 0;
      }
   }

   return 1;
}

static void
_local_cmd_send_accept(chann_t *n, uint8_t val) {
   uint8_t ss[2] = {0x05, val};
   mnet_chann_send(n, ss, 2);
}

static void
_local_cmd_fail_to_connect(chann_t *n) {
   /* fail to connect */
   uint8_t es[10] = {0x05, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
   mnet_chann_send(n, es, 10);
}

static void
_local_cmd_send_connected(tun_local_chann_t *c, uint8_t *addr, int port) {
   uint8_t es[10] = {
      0x05, 0x00, 0x00, 0x01,
      addr[0], addr[1], addr[2], addr[3],
      ((port & 0xff00)>>8), (port&0xff)
   };

   /* _print_hex(es, 10); */
   mnet_chann_send(c->tcpin, es, 10);
   c->state = LOCAL_CHANN_STATE_CONNECTED;
}


void
_tun_local_chann_tcpin_cb_standalone(chann_event_t *e) {
   //tun_local_t *tun = _tun_local();
   tun_local_chann_t *c = (tun_local_chann_t*)e->opaque;

   if (e->event == MNET_EVENT_RECV) {
      buf_t *ib = c->bufin;
      int ret = mnet_chann_recv(e->n, buf_addr(ib, buf_ptw(ib)), buf_available(ib));
      if (ret <= 0) {
         return;
      }
      buf_forward_ptw(ib, ret);

      if (c->state == LOCAL_CHANN_STATE_CONNECTED) {
         //_verbose("(out) send data %d\n", buf_buffered(ib));
         mnet_chann_send(c->tcpout, buf_addr(ib,buf_ptr(ib)), buf_buffered(ib));
      }
      else if (c->state == LOCAL_CHANN_STATE_NONE && buf_buffered(ib)>=3) {

         uint8_t rs[3] = {0x05, 0x01, 0x00};
         if ( _hex_equal(buf_addr(ib,buf_ptr(ib)), buf_buffered(ib), rs, 3) ) {
            //_verbose("(in) accept %p, %d\n", e->n, lst_count(tun->active_lst));
            c->state = LOCAL_CHANN_STATE_ACCEPT;
            _local_cmd_send_accept(c->tcpin, 00);
         }
      }
      else if (c->state == LOCAL_CHANN_STATE_ACCEPT && buf_buffered(ib)>=10) {
         uint8_t *rd = buf_addr(ib, buf_ptr(ib));
         uint8_t rs[4] = {0x05, 0x01, 0x00};
         if ( _hex_equal(rd, buf_buffered(ib), rs, 3) ) {
            if (rd[3] == 0x01) { /* IPV4 */
               rd = &rd[4];

               char addr[TUNNEL_DNS_ADDR_LEN] = {0};
               snprintf(addr, TUNNEL_DNS_ADDR_LEN, "%d.%d.%d.%d", rd[0], rd[1], rd[2], rd[3]);

               int port = (rd[4]<<8) | rd[5];
               if (_tun_local_chann_tcpout_create(c, addr, port) <= 0) {
                  _local_cmd_fail_to_connect(c->tcpin);
               }
            }
            else if (rd[3] == 0x03) { /* domain */
               uint8_t dlen = (uint8_t)rd[4];
               char *domain = (char*)&rd[5];
               int port = (rd[5+dlen]<<8) | rd[6+dlen];

               char addr[TUNNEL_DNS_DOMAIN_LEN] = {0};
               //_verbose("(in_recv) %d, %s\n", dlen, domain);

               if ( dns_domain_query_ip(domain, dlen, addr, TUNNEL_DNS_DOMAIN_LEN) ) {
                  if (_tun_local_chann_tcpout_create(c, addr, port) <= 0) {
                     _local_cmd_fail_to_connect(c->tcpin);
                  }
               }
               else {
                  _err("Invalid DNS [%s]\n", misc_fix_str_1024(domain, dlen));
               }
            }
         }
      }

      //_print_hex(buf_addr(ib,buf_ptr(ib)), buf_buffered(ib));
      //_verbose("ipaddr:%s\n", mnet_chann_addr(e->n));
      //_verbose("(in_recv) %d\n", ret);
      buf_reset(ib);
   }
   else if (e->event == MNET_EVENT_CLOSE) {
      _tun_local_chann_disable(c);
      _tun_local_chann_close(c);
   }
   //buf_debug(b);
}

void
_tun_local_chann_tcpout_cb_standalone(chann_event_t *e) {
   tun_local_chann_t *c = (tun_local_chann_t*)e->opaque;

   if (e->event == MNET_EVENT_CONNECT) {
      char addr_str[TUNNEL_DNS_ADDR_LEN] = {0};
      int port = mnet_chann_port(e->n);
      sprintf(addr_str, "%s", mnet_chann_addr(e->n));

      uint8_t addr_ip[4] = {0};
      misc_hex_addr(addr_str, strlen(addr_str), addr_ip, 4);

      //_verbose("(out) connected %s:%d]\n", addr_str, port);
      _local_cmd_send_connected(c, addr_ip, port);
   }
   else if (e->event == MNET_EVENT_RECV) {
      if (c->state == LOCAL_CHANN_STATE_CONNECTED) {
         buf_t *ob = c->bufout;
         int ret = mnet_chann_recv(e->n, buf_addr(ob,buf_ptw(ob)), buf_available(ob));
         if (ret > 0) {
            buf_forward_ptw(ob, ret);
            mnet_chann_send(c->tcpin, buf_addr(ob,buf_ptr(ob)), buf_buffered(ob));
            //_verbose("(out) recv data %d\n", buf_buffered(cb));
         }
         buf_reset(ob);
      }
   }
   else if (e->event == MNET_EVENT_CLOSE) {
      _tun_local_chann_disable(c);
      _tun_local_chann_close(c);
   }
}

static void
_tun_local_listen_cb(chann_event_t *e) {
   if (e->event == MNET_EVENT_ACCEPT) {
      tun_local_t *tun = _tun_local();
      if (tun->chann_idx < TUNNEL_CHANN_MAX_COUNT) {
         _tun_local_chann_open(e->r);
      }
      else {
         mnet_chann_close(e->r);
      }
   }
}

/* 
 */

int
tunnel_local_open(tunnel_local_config_t *conf) {
   tun_local_t *tun = _tun_local();
   if (conf && !tun->running) {
      memset(tun, 0, sizeof(*tun));

      tun->conf = *conf;
      tun->active_lst = lst_create();
      tun->free_lst = lst_create();

      tun->tcpin = mnet_chann_open(CHANN_TYPE_STREAM);
      mnet_chann_set_cb(tun->tcpin, _tun_local_listen_cb, tun);
      mnet_chann_listen_ex(tun->tcpin, conf->local_ipaddr, conf->local_port, 1);

      tun->mode = conf->mode;
      tun->running = 1;

      _info("local open mode %d\n", tun->mode);
      _info("local listen on %s:%d\n", conf->local_ipaddr, conf->local_port);
      _info("\n");

      return 1;
   }
   return 0;
}

#if 0
void
tunnel_local_close(void) {
   tun_local_t *tun = _tun_local();
   if (tun->running) {
      while (lst_count(tun->channs_lst) > 0) {
         tun_local_chann_t *c = (tun_local_chann_t*)lst_first(tun->channs_lst);
         if (tun->mode == TUNNEL_LOCAL_MODE_STANDALONE) {
            _tun_local_chann_tcpout_destroy(c, 0);
         }
         _tun_local_chann_tcpin_destroy(c, 0);
      }
      lst_destroy(tun->channs_lst);
      mnet_chann_close(tun->tcpin);
      mnet_chann_set_cb(tun->tcpin, NULL, NULL);

      memset(tun, 0, sizeof(*tun));
      _info("\n");
      _info("local close listen, bye !\n");
      _info("\n");
   }
}
#endif

static void
_tun_local_sig_timer(int sig) {
   tun_local_t *tun = _tun_local();
   tun->timer_active = 1;
}

static int
_tun_local_install_sig_timer() {
   struct itimerval tick;
   tick.it_value.tv_sec = 15;
   tick.it_value.tv_usec = 0;
   tick.it_interval.tv_sec = 15; /* 15 s */
   tick.it_interval.tv_usec = 0;
   if (signal(SIGALRM, _tun_local_sig_timer) == SIG_ERR) {
      fprintf(stderr, "Fail to install signal\n");
      return 0;
   }

   if (setitimer(ITIMER_REAL, &tick, NULL) != 0) {
      fprintf(stderr, "Fail to set timer\n");
      return 0;
   }
   return 1;
}

static void
_local_conf_get_values(tunnel_local_config_t *conf, char *argv[]) {

   conf_t *cf = utils_conf_open(argv[1]);
   if (cf == NULL) {
      _err("fail to get conf from [%s]\n", argv[1]);
      goto fail;
   }

   str_t *value = NULL;

   char dbg_fname[32] = {0};

   value = utils_conf_value(cf, "DEBUG_FILE");
   strncpy(dbg_fname, str_cstr(value), str_len(value));

   value = utils_conf_value(cf, "LOCAL_MODE");
   if (str_cmp(value, "STANDALONE", 0) == 0) {
      conf->mode = TUNNEL_LOCAL_MODE_STANDALONE;
   } else {
      goto fail;
   }

   value = utils_conf_value(cf, "LOCAL_IP");
   strncpy(conf->local_ipaddr, str_cstr(value), str_len(value));
   conf->local_port = atoi(str_cstr(utils_conf_value(cf, "LOCAL_PORT")));

   value = utils_conf_value(cf, "RUN_DAEMON");
   if (str_cmp(value, "YES", 0) == 0) {
      //daemon(1, 0);
   }
   
  fail:
   utils_conf_close(cf);

   debug_open(dbg_fname);
   debug_set_option(D_OPT_TIME);
   debug_set_level(D_VERBOSE);
}

int
main(int argc, char *argv[]) {

   if (argc != 2) {
      fprintf(stderr, "[local] %s LOCAL_CONFIG_FILE\n", argv[0]);
      return 0;
   }

   signal(SIGPIPE, SIG_IGN);

   if (_tun_local_install_sig_timer() <= 0) {
      fprintf(stderr, "[local] fail to install sig timer !\n");
      return 0;
   }

   tunnel_local_config_t conf = {TUNNEL_LOCAL_MODE_INVALID,0,0, "", ""};

   _local_conf_get_values(&conf, argv);

   if (conf.mode == TUNNEL_LOCAL_MODE_STANDALONE)
   {
      mnet_init();

      if (tunnel_local_open(&conf) > 0) {

         dns_restore(TUN_LOCAL_DNS_FILE_NAME, TUN_LOCAL_BLOCK_FILE_NAME);

         for (int i=0;;i++) {

            mnet_check( -1 );
         }

          //tunnel_local_close();
      }

      mnet_fini();
   }
   else {
      _err("invalid tunnel mode %d !\n", conf.mode);
   }

   debug_close();
   return 0;
}

#endif
