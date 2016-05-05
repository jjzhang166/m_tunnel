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
#include <time.h>
#include <signal.h>
#include <sys/time.h>

#include "m_mem.h"
#include "m_list.h"
#include "m_stm.h"
#include "m_debug.h"

#include "plat_net.h"
#include "plat_time.h"
#include "plat_thread.h"

#include "utils_str.h"
#include "utils_conf.h"
#include "utils_misc.h"

#include "tunnel_cmd.h"
#include "tunnel_dns.h"
#include "tunnel_remote.h"
#include "tunnel_crypto.h"

#include <assert.h>

#define _err(...) _mlog("remote", D_ERROR, __VA_ARGS__)
#define _info(...) _mlog("remote", D_INFO, __VA_ARGS__)
#define _verbose(...) _mlog("remote", D_VERBOSE, __VA_ARGS__)

#ifdef TEST_TUNNEL_REMOTE

typedef enum {
   REMOTE_CLIENT_STATE_NONE = 0,
   REMOTE_CLIENT_STATE_ACCEPT,  /* AUTH successful */
} remote_client_state_t;

/* chann state to front */
typedef enum {
   REMOTE_CHANN_STATE_NONE = 0,
   REMOTE_CHANN_STATE_DISCONNECT, /* chann disconnect from tcpin */
   REMOTE_CHANN_STATE_CONNECTED,  /* chann tcpout connected */
} remote_chann_state_t;

typedef struct {
   char addr[TUNNEL_DNS_ADDR_LEN];
   int port;
   int chann_id;
   int magic;
   void *opaque;
} dns_query_t;

typedef struct {
   remote_chann_state_t state;
   int chann_id;                /* chann id in slots */
   int magic;                   /* from local chann magic */
   chann_t *tcpout;
   buf_t *bufout;
   lst_node_t *node;            /* node in active_lst */
   void *client;                /* client pointer */
} tun_remote_chann_t;

typedef struct {
   int data_mark;
   remote_client_state_t state;
   chann_t *tcpin;
   buf_t *bufin;
   lst_t *active_lst;
   lst_t *free_lst;
   lst_node_t *node;            /* node in clients_lst */
   tun_remote_chann_t *channs[TUNNEL_CHANN_MAX_COUNT];
} tun_remote_client_t;

typedef struct {
   int running;
   time_t ti;
   uint64_t key;
   int timer_active;
   tunnel_remote_mode_t mode;
   tunnel_remote_config_t conf;
   chann_t *tcpin;
   chann_t *tcpout;             /* for mode forward */
   buf_t *buftmp;               /* buf for crypto */
   lst_t *clients_lst;          /* acitve cilent */
   lst_t *leave_lst;            /* client to leave */
   stm_t *ip_stm;
} tun_remote_t;

static tun_remote_t _g_remote;

static void _remote_tcpout_cb(chann_event_t *e);
static void _remote_tcpin_cb(chann_event_t *e);
static void _remote_chann_closing(tun_remote_chann_t*);
static void _remote_chann_close(tun_remote_chann_t*);

static inline tun_remote_t* _tun_remote(void) {
   return &_g_remote;
}

static dns_query_t*
_dns_query_create(int port, int chann_id, int magic, void *opaque) {
   dns_query_t *q = (dns_query_t*)mm_malloc(sizeof(*q));
   q->port = port;
   q->chann_id = chann_id;
   q->magic = magic;
   q->opaque = opaque;
   return q;
}

static void
_dns_query_destroy(dns_query_t *query) {
   mm_free(query);
}

static tun_remote_client_t*
_remote_client_create(chann_t *n) {
   tun_remote_t *tun = _tun_remote();
   tun_remote_client_t *c = (tun_remote_client_t*)mm_malloc(sizeof(*c));
   c->tcpin = n;
   c->bufin = buf_create(TUNNEL_CHANN_BUF_SIZE);
   assert(c->bufin);
   c->active_lst = lst_create();
   c->free_lst = lst_create();
   c->node = lst_pushl(tun->clients_lst, c);
   mnet_chann_set_cb(n, _remote_tcpin_cb, c);
   //_verbose("client create %p(%p), %d\n", c, c->tcpin, lst_count(tun->clients_lst));
   return c;
}

static void
_remote_client_destroy(tun_remote_client_t *c) {
   tun_remote_t *tun = _tun_remote();
   if (c->node) {
      mnet_chann_set_cb(c->tcpin, NULL, NULL);
      if (mnet_chann_state(c->tcpin) >= CHANN_STATE_CONNECTING) {
         mnet_chann_close(c->tcpin);
      }

      buf_destroy(c->bufin);
      c->bufin = NULL;

      while (lst_count(c->active_lst) > 0) {
         tun_remote_chann_t *rc = lst_first(c->active_lst);
         _remote_chann_closing(rc);
         _remote_chann_close(rc);
      }
      lst_destroy(c->active_lst);

      while (lst_count(c->free_lst) > 0) {
         tun_remote_chann_t *rc = lst_popf(c->free_lst);
         buf_destroy(rc->bufout);
         mm_free(rc);
      }
      lst_destroy(c->free_lst);

      lst_remove(tun->clients_lst, c->node);
      c->node = NULL;
      mm_free(c);
      _verbose("client destroy %p\n", c);
   }
}

static tun_remote_chann_t*
_remote_chann_open(tun_remote_client_t *c, tunnel_cmd_t *tcmd, char *addr, int port) {
   tun_remote_chann_t *rc = NULL;
   if ( c->channs[tcmd->chann_id] ) {
      return c->channs[tcmd->chann_id];
   }

   if (lst_count(c->free_lst) > 0) {
      rc = lst_popf(c->free_lst);
   } else {
      rc = (tun_remote_chann_t*)mm_malloc(sizeof(*rc));
      rc->bufout = buf_create(TUNNEL_CHANN_BUF_SIZE);
      assert(rc->bufout);
   }
   rc->chann_id = tcmd->chann_id;
   rc->magic = tcmd->magic;
   rc->client = (void*)c;
   rc->node = lst_pushl(c->active_lst, rc);
   rc->tcpout = mnet_chann_open(CHANN_TYPE_STREAM);

   c->channs[tcmd->chann_id] = rc;
   mnet_chann_set_cb(rc->tcpout, _remote_tcpout_cb, rc);

   if (mnet_chann_connect(rc->tcpout, addr, port) > 0) {
      /* _verbose("chann %d:%d open, [a:%d, f:%d]\n", rc->chann_id, rc->magic, */
      /*          lst_count(c->active_lst), lst_count(c->free_lst)); */
      return rc;
   }
   _err("chann fail to open %d, %p\n", tcmd->chann_id, c);
   return NULL;
}

void
_remote_chann_closing(tun_remote_chann_t *rc) {
   /* _verbose("chann %d:%d closing %p\n", rc->chann_id, rc->magic, rc); */

   rc->state = REMOTE_CHANN_STATE_DISCONNECT;

   if (mnet_chann_state(rc->tcpout) >= CHANN_STATE_CONNECTING) {
      mnet_chann_close(rc->tcpout);
   }   
}

void
_remote_chann_close(tun_remote_chann_t *rc) {
   tun_remote_client_t *c = (tun_remote_client_t*)rc->client;
   if (c->node) {
      _verbose("chann %d:%d close [a:%d, f:%d]\n", rc->chann_id, rc->magic,
               lst_count(c->active_lst), lst_count(c->free_lst));

      mnet_chann_set_cb(rc->tcpout, NULL, NULL);
      _remote_chann_closing(rc);

      c->channs[rc->chann_id] = NULL;
      rc->chann_id = 0;

      lst_remove(c->active_lst, rc->node);
      lst_pushl(c->free_lst, rc);

      rc->node = NULL;
      rc->state = REMOTE_CHANN_STATE_NONE;
   }
}

static tun_remote_chann_t*
_remote_chann_of_id_magic(tun_remote_client_t *c, int chann_id, int magic) {
   if (c) {
      if (chann_id>=0 && chann_id<TUNNEL_CHANN_MAX_COUNT) {
         tun_remote_chann_t *rc = c->channs[chann_id];
         if (rc && (rc->magic==magic)) {
            return rc;
         }
         _err("invalid remote chann %d:%d\n", chann_id, magic);
      }
   }
   return NULL;
}

static void
_remote_aux_dns_cb(char *addr, int addr_len, void *opaque) {
   tun_remote_t *tun = _tun_remote();
   dns_query_t *q = (dns_query_t*)opaque;

   if (addr) {
      strncpy(q->addr, addr, addr_len);
   }
   else {
      q->port = 0;
   }

   stm_pushl(tun->ip_stm, q);
}

static int
_remote_send_front_data(tun_remote_client_t *c, unsigned char *buf, int buf_len) {

#ifdef DEF_TUNNEL_SIMPLE_CRYPTO
   mc_enc_exp(&buf[3], buf_len-3);
   return mnet_chann_send(c->tcpin, buf, buf_len);
#else
   tun_remote_t *tun = _tun_remote();
   char *tbuf = (char*)buf_addr(tun->buftmp,0);

   int data_len = mc_encrypt((char*)&buf[3], buf_len-3, &tbuf[3], tun->key, tun->ti);
   assert(data_len > 0);

   tunnel_cmd_data_len((void*)tbuf, 1, data_len + 3);   
   return mnet_chann_send(c->tcpin, tbuf, data_len + 3);
#endif
}

static void
_remote_recv_front_data(tun_remote_client_t *c, buf_t *b) {
   char *buf = (char*)buf_addr(b,0);
   int buf_len = buf_buffered(b);

#ifdef DEF_TUNNEL_SIMPLE_CRYPTO
   mc_dec_exp((unsigned char*)&buf[3], buf_len-3);
#else
   tun_remote_t *tun = _tun_remote();
   char *tbuf = (char*)buf_addr(tun->buftmp,0);

   int data_len = mc_decrypt(&buf[3], buf_len-3, tbuf, tun->key, tun->ti);
   assert(data_len > 0);

   memcpy(&buf[3], tbuf, data_len);
   tunnel_cmd_data_len((void*)buf, 1, data_len + 3);

   buf_reset(b);
   buf_forward_ptw(b, data_len + 3);
#endif
}

static void
_remote_send_connect_result(tun_remote_client_t *c, int chann_id, int magic, int result) {
   unsigned char data[32] = {0};

   int hlen = TUNNEL_CMD_CONST_HEADER_LEN;
   int data_len = hlen + 7;

   tunnel_cmd_data_len(data, 1, data_len);
   tunnel_cmd_chann_id(data, 1, chann_id);
   tunnel_cmd_chann_magic(data, 1, magic);
   tunnel_cmd_head_cmd(data, 1, TUNNEL_CMD_CONNECT);
   
   data[hlen] = result;

   if (result > 0) {
      tun_remote_chann_t *rc = _remote_chann_of_id_magic(c, chann_id, magic);

      if (rc) {
         int port = mnet_chann_port(rc->tcpout);
         data[hlen + 1] = (port >> 8) & 0xff;
         data[hlen + 2] = port & 0xff;

         char *addr_str = mnet_chann_addr(rc->tcpout);
         misc_hex_addr(addr_str, strlen(addr_str), &data[hlen+3], 4);

#if 0
         {
            unsigned char *d = &data[hlen + 3];
            _verbose("chann %d:%d connected [%s:%d], [%d.%d.%d.%d:%d]\n",
                     chann_id, magic, addr_str, port, d[0], d[1], d[2], d[3], port);
         }
#endif
      }
   }

   int ret = _remote_send_front_data(c, data, data_len);
   if (ret < data_len) {
      _err("fail to send connect result %d, %d!\n", ret, data_len);
   }
         
   //_info("chann %p send chann (%d) connection result %d\n", c, chann_id, result);
}

static inline void
_remote_update_ti() {
   _tun_remote()->ti = time(NULL);
}

static void
_remote_send_echo(tun_remote_client_t *c) {
   unsigned char data[32] = {0};
   int data_len = TUNNEL_CMD_CONST_HEADER_LEN + 1;
   memset(data, 0, sizeof(data));

   tunnel_cmd_data_len(data, 1, data_len);
   tunnel_cmd_chann_id(data, 1, 0);
   tunnel_cmd_chann_magic(data, 1, 0);
   tunnel_cmd_head_cmd(data, 1, TUNNEL_CMD_ECHO);
   data[data_len - 1] = 1;

   _remote_send_front_data(c, data, data_len);
   _remote_update_ti();

   _verbose("response echo to %p\n", c);
}

static void
_remote_send_close(tun_remote_client_t *c, tun_remote_chann_t *rc, int result) {
   unsigned char data[16] = {0};

   int data_len = TUNNEL_CMD_CONST_HEADER_LEN + 1;

   tunnel_cmd_data_len(data, 1, data_len);
   tunnel_cmd_chann_id(data, 1, rc->chann_id);
   tunnel_cmd_chann_magic(data, 1, rc->magic);
   tunnel_cmd_head_cmd(data, 1, TUNNEL_CMD_CLOSE);

   data[data_len - 1] = result; /* omit */

   _remote_send_front_data(c, data, data_len);
}

void
_remote_tcpin_cb(chann_event_t *e) {
   tun_remote_client_t *c = (tun_remote_client_t*)e->opaque;
   if (c->bufin == NULL) {
      return;
   }

   if (e->event == MNET_EVENT_RECV) {
      tunnel_cmd_t tcmd = {0, 0, 0, 0, NULL};

      for (;;) {
         int ret = 0;
         buf_t *ib = c->bufin;

         if (buf_buffered(ib) < TUNNEL_CMD_CONST_HEADER_LEN) {
            ret = mnet_chann_recv(e->n, buf_addr(ib,buf_ptw(ib)), TUNNEL_CMD_CONST_HEADER_LEN - buf_buffered(ib));
         } else {
            tunnel_cmd_check(ib, &tcmd);
            ret = mnet_chann_recv(e->n, buf_addr(ib,buf_ptw(ib)), tcmd.data_len - buf_buffered(ib));
         }

         if (ret <= 0) {
            return;
         }
         buf_forward_ptw(ib, ret);

         if (buf_buffered(ib) <= TUNNEL_CMD_CONST_HEADER_LEN) {
            continue;
         }
         if (tcmd.data_len != buf_buffered(ib)) {
            return;
         }

         /* decode data */
         _remote_recv_front_data(c, ib);

         /* _verbose("%d, %d\n", tcmd.data_len, buf_buffered(ib)); */
         tunnel_cmd_check(ib, &tcmd);
         if (tcmd.cmd<=TUNNEL_CMD_NONE || tcmd.cmd>TUNNEL_CMD_DATA) {
            assert(0);
         }

         c->data_mark++;

         if (tcmd.cmd == TUNNEL_CMD_ECHO) {
            _remote_send_echo(c);
            goto reset_buffer;
         }

         /* _info("get cmd %d\n", tcmd.cmd); */
         if (c->state == REMOTE_CLIENT_STATE_ACCEPT) {

            if (tcmd.cmd == TUNNEL_CMD_DATA) {
               tun_remote_chann_t *rc = _remote_chann_of_id_magic(c, tcmd.chann_id, tcmd.magic);

               if (rc && rc->state==REMOTE_CHANN_STATE_CONNECTED) {
                  int hlen = TUNNEL_CMD_CONST_HEADER_LEN;
                  mnet_chann_send(rc->tcpout, tcmd.payload, tcmd.data_len - hlen);
               }
            }
            else if (tcmd.cmd == TUNNEL_CMD_CONNECT) {
               unsigned char *payload = tcmd.payload;
               unsigned char addr_type = payload[0];

               int port = ((payload[1] & 0xff) << 8) | (payload[2] & 0xff);
               /* _verbose("chann %d addr_type %d\n", tcmd.chann_id, addr_type); */

               if (addr_type == TUNNEL_ADDR_TYPE_IP) {
                  char addr[TUNNEL_DNS_ADDR_LEN] = {0};

                  strcpy(addr, (const char*)&payload[3]);
                  _verbose("chann %d:%d try connect ip [%s:%d], %d\n", tcmd.chann_id,
                           tcmd.magic, addr, port, strlen(addr));

                  tun_remote_chann_t *rc = _remote_chann_open(c, &tcmd, addr, port);
                  if (rc == NULL) {
                     _remote_send_connect_result(c, tcmd.chann_id, tcmd.magic, 0);
                  }
               }
               else {
                  char addr[TUNNEL_DNS_DOMAIN_LEN] = {0};
                  char domain[TUNNEL_DNS_DOMAIN_LEN] = {0};

                  strcpy(domain, (const char*)&payload[3]);
                  _verbose("chann %d:%d query domain [%s:%d], %d\n", tcmd.chann_id,
                           tcmd.magic, domain, port, strlen(addr));
                  
                  dns_query_t *query_entry = _dns_query_create(port, tcmd.chann_id, tcmd.magic, c);
                  dns_query_domain(domain, strlen(domain), _remote_aux_dns_cb, query_entry);
               }
            }
            else if (tcmd.cmd == TUNNEL_CMD_CLOSE) {
               tun_remote_chann_t *rc = _remote_chann_of_id_magic(c, tcmd.chann_id, tcmd.magic);
               if (rc) {
                  _remote_chann_closing(rc);
               }
            }
         }
         else {
            if (tcmd.cmd == TUNNEL_CMD_AUTH) {
               unsigned char data[64] = {0};
               int data_len = TUNNEL_CMD_CONST_HEADER_LEN + 1;

               int auth_type = tcmd.payload[0];
            
               if (auth_type == 1) {
                  char *username = (char*)&tcmd.payload[1];
                  char *passwd = (char*)&tcmd.payload[17];

                  tunnel_cmd_data_len(data, 1, data_len);
                  tunnel_cmd_chann_id(data, 1, 0);
                  tunnel_cmd_chann_magic(data, 1, 0);
                  tunnel_cmd_head_cmd(data, 1, TUNNEL_CMD_AUTH);

                  tun_remote_t *tun = _tun_remote();
                  if (strncmp(tun->conf.username, username, 16)==0 &&
                      strncmp(tun->conf.password, passwd, 16)==0)
                  {
                     c->state = REMOTE_CLIENT_STATE_ACCEPT;
                     data[data_len - 1] = 1;
                     _remote_send_front_data(c, data, data_len);
                  }
                  else {
                     data[data_len - 1] = 0;
                     _err("fail to auth <%s>, <%s>\n", username, passwd);
                     _remote_client_destroy(c);
                  }
               }
               _verbose("(in) accept client %p, %d\n", c, auth_type);
            }
            else {
               assert(0);
            }
         }
        reset_buffer:
         buf_reset(ib);
      }
   }
   else if (e->event == MNET_EVENT_CLOSE) {
      _verbose("client close event !\n");
      lst_pushl(_tun_remote()->leave_lst, c);
   }
}

static inline int
_remote_buf_available(buf_t *b) {
   /* for crypto, keep least 8 bytes */
   return (buf_available(b) - TUNNEL_CMD_CONST_HEADER_LEN);
}

void
_remote_tcpout_cb(chann_event_t *e) {
   tun_remote_chann_t *rc = (tun_remote_chann_t*)e->opaque;
   tun_remote_client_t *c = (tun_remote_client_t*)rc->client;
   
   if (rc->bufout == NULL) {
      return;
   }

   if (e->event == MNET_EVENT_RECV) {
      if (c->state == REMOTE_CLIENT_STATE_ACCEPT) {
         buf_t *ob = rc->bufout;
         int hlen = TUNNEL_CMD_CONST_HEADER_LEN;
         int ret = mnet_chann_recv(e->n, buf_addr(ob,hlen), _remote_buf_available(ob) - hlen);
         if (ret <= 0) {
            return;
         }
         int data_len = ret + hlen;
         buf_forward_ptw(ob, data_len);

         unsigned char *data = buf_addr(ob,0);

         tunnel_cmd_data_len(data, 1, data_len);
         tunnel_cmd_chann_id(data, 1, rc->chann_id);
         tunnel_cmd_chann_magic(data, 1, rc->magic);
         tunnel_cmd_head_cmd(data, 1, TUNNEL_CMD_DATA);

         _remote_send_front_data(c, data, data_len);

         buf_reset(ob);
      }
   }
   else if (e->event == MNET_EVENT_CONNECT) {
      if (rc->state == REMOTE_CHANN_STATE_NONE) {
         _verbose("chann %d:%d connected\n", rc->chann_id, rc->magic);
         rc->state = REMOTE_CHANN_STATE_CONNECTED;
         _remote_send_connect_result(c, rc->chann_id, rc->magic, 1);
      }
   }
   else if (e->event == MNET_EVENT_DISCONNECT) {
      _verbose("chann %d disconnect\n", rc->chann_id);
      if (rc->state == REMOTE_CHANN_STATE_NONE) {
         _remote_send_connect_result(c, rc->chann_id, rc->magic, 0);
      }
      else if (rc->state == REMOTE_CHANN_STATE_CONNECTED) {
         _remote_send_close(c, rc, 1);
         _remote_chann_closing(rc);
      }
   }
   else if (e->event == MNET_EVENT_CLOSE) {
      _verbose("chann %d close, mnet\n", rc->chann_id);
      _remote_send_close(c, rc, 1);
      _remote_chann_close(rc);
   }
}

static void
_remote_listen_cb(chann_event_t *e) {
   if (e->event == MNET_EVENT_ACCEPT) {
      tun_remote_t *tun = _tun_remote();
      if (lst_count(tun->clients_lst) < 6) {
         _remote_client_create(e->r);
      }
   }
}

static void
_remote_stm_finalizer(void *ptr, void *ud) {
   mm_free(ptr);
}

/*
 */

int
tunnel_remote_open(tunnel_remote_config_t *conf) {
   tun_remote_t *tun = _tun_remote();
   if (conf && !tun->running) {
      memset(tun, 0, sizeof(*tun));

      tun->conf = *conf;
      tun->clients_lst = lst_create();
      tun->leave_lst = lst_create();
      tun->ip_stm = stm_create("remote_dns_cache", _remote_stm_finalizer, tun);

      tun->tcpin = mnet_chann_open(CHANN_TYPE_STREAM);
      mnet_chann_set_cb(tun->tcpin, _remote_listen_cb, tun);
      if (mnet_chann_listen_ex(tun->tcpin, conf->local_ipaddr, conf->local_port, 2) <= 0) {
         exit(1);
      }

      tun->buftmp = buf_create(TUNNEL_CHANN_BUF_SIZE);
      assert(tun->buftmp);

      tun->mode = conf->mode;
      tun->running = 1;

      _info("remote open mode %d\n", tun->mode);
      _info("remote listen on %s:%d\n", conf->local_ipaddr, conf->local_port);
      _info("\n");

      return 1;
   }
   return 0;
}

#if 0
void
tunnel_remote_close(void) {
   tun_remote_t *tun = _tun_remote();
   if (tun->running) {
      _info("\n");
      _info("remote close listen, bye !\n");
      _info("\n");      
   }
}
#endif

static void
_remote_sig_timer(int sig) {
   tun_remote_t *tun = _tun_remote();
   tun->timer_active = 1;
}

static int
_remote_install_sig_timer() {
   struct itimerval tick;
   tick.it_value.tv_sec = 60;
   tick.it_value.tv_usec = 0;
   tick.it_interval.tv_sec = 60; /* 60 s */
   tick.it_interval.tv_usec = 0;
   if (signal(SIGALRM, _remote_sig_timer) == SIG_ERR) {
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
_remote_conf_get_values(tunnel_remote_config_t *conf, char *argv[]) {

   conf_t *cf = utils_conf_open(argv[1]);
   if (cf == NULL) {
      _err("fail to get conf from [%s]\n", argv[1]);
      goto fail;
   }

   str_t *value = NULL;

   char dbg_fname[32] = {0};

   value = utils_conf_value(cf, "DEBUG_FILE");
   strncpy(dbg_fname, str_cstr(value), str_len(value));

   value = utils_conf_value(cf, "REMOTE_MODE");
   if (str_cmp(value, "STANDALONE", 0) == 0) {
      conf->mode = TUNNEL_REMOTE_MODE_STANDALONE;
   } else if (str_cmp(value, "FORWARD", 0) == 0) {
      conf->mode = TUNNEL_REMOTE_MODE_FORWARD;
   } else {
      goto fail;
   }

   value = utils_conf_value(cf, "REMOTE_IP");
   strncpy(conf->local_ipaddr, str_cstr(value), str_len(value));
   conf->local_port = atoi(str_cstr(utils_conf_value(cf, "REMOTE_PORT")));

   if (conf->mode == TUNNEL_REMOTE_MODE_FORWARD) {
      value = utils_conf_value(cf, "FORWARD_IP");
      strncpy(conf->forward_ipaddr, str_cstr(value), str_len(value));
      conf->forward_port = atoi(str_cstr(utils_conf_value(cf, "FORWARD_PORT")));
   }

   value = utils_conf_value(cf, "REMOTE_USERNAME");
   if (value) {
      strncpy(conf->username, str_cstr(value), _MIN_OF(str_len(value), 32));
   }

   value = utils_conf_value(cf, "REMOTE_PASSWORD");
   if (value) {
      strncpy(conf->password, str_cstr(value), _MIN_OF(str_len(value), 32));
   }

   value = utils_conf_value(cf, "RUN_DAEMON");
   if (str_cmp(value, "YES", 0) == 0) {
      //daemon(1, 0);
   }
   
  fail:
   utils_conf_close(cf);

   debug_open(dbg_fname);
   debug_set_option(D_OPT_FILE);
   debug_set_level(D_VERBOSE);
}

int
main(int argc, char *argv[]) {
   if (argc != 2) {
      printf("[remote] %s REMOTE_CONFIG_FILE\n", argv[0]);
      return 0;
   }

   signal(SIGPIPE, SIG_IGN);

   if (_remote_install_sig_timer() <= 0) {
      fprintf(stderr, "[local] fail to install sig timer !\n");
      return 0;
   }

   tunnel_remote_config_t conf = {TUNNEL_REMOTE_MODE_INVALID, 0, 0, "", ""};

   _remote_conf_get_values(&conf, argv);

   if (conf.mode == TUNNEL_REMOTE_MODE_STANDALONE ||
       conf.mode == TUNNEL_REMOTE_MODE_FORWARD)
   {
      mnet_init();
      stm_init();
      mthrd_init(MTHRD_MODE_POWER_HIGH);

      if (tunnel_remote_open(&conf) > 0) {
         tun_remote_t *tun = _tun_remote();

         tun->key = mc_hash_key(conf.password, strlen(conf.password));

         for (int i=0;;i++) {

            if (i > TUNNEL_CHANN_MAX_COUNT) {
               i = 0; 
               mtime_sleep(1);
            }

            _remote_update_ti();
            mnet_check( -1 );


            /* close inactive client */
            while (lst_count(tun->leave_lst) > 0) {
               _remote_client_destroy(lst_popf(tun->leave_lst));
            }


            /* check dns ip_stm */
            while (stm_count(tun->ip_stm) > 0) {
               dns_query_t *q = stm_popf(tun->ip_stm);
               tun_remote_client_t *c = q->opaque;

               int client_exist = 0;

               lst_foreach(it, tun->clients_lst) {
                  tun_remote_client_t *lc = lst_iter_data(it);
                  if (lc == c) {
                     client_exist = 1;
                     break;
                  }
               }

               if (client_exist) {
                  tunnel_cmd_t tcmd;
                  int is_connect = 1;

                  tcmd.chann_id = q->chann_id;
                  tcmd.magic = q->magic;

                  if (q->port <= 0) {
                     is_connect = 0;
                  }
                  else {
                     tun_remote_chann_t *rc = _remote_chann_open(c, &tcmd, q->addr, q->port);
                     if (rc == NULL) {
                        is_connect = 0;
                     }
                  }

                  if ( !is_connect ) {
                     _remote_send_connect_result(c, tcmd.chann_id, tcmd.magic, 0);
                  }
               }
               
               _dns_query_destroy(q);
            }


            /* mem report */
            if (tun->timer_active > 0) {
               tun->timer_active = 0;
               mm_report(1);
               _verbose("chann count %d\n", mnet_report(0));
            }
         }

         //tunnel_remote_close();
      }
      else {
         _err("invalid tunnel mode %d !\n", conf.mode);
      }

      mthrd_fini();
      stm_fini();
      mnet_fini();
   }
   else {
      _err("invalide remote mode %d !\n", conf.mode);
   }

   debug_close();
   return 0;
}

#endif
