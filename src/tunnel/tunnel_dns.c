/* 
 * Copyright (c) 2015 lalawue
 * 
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the MIT license. See LICENSE for details.
 */

#define _POSIX_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>

#include "m_mem.h"
#include "m_dict.h"
#include "m_list.h"
#include "m_stm.h"
#include "m_debug.h"

#include "plat_time.h"
#include "plat_thread.h"

//#include "utils_str.h"
#include "utils_misc.h"

#include "tunnel_dns.h"

#include "plat_lock.h"
#include "plat_thread.h"

#include <assert.h>

#define _err(...) _mlog("dsn", D_ERROR, __VA_ARGS__)
#define _info(...) _mlog("dns", D_INFO, __VA_ARGS__)

#ifndef DEF_TUNNEL_DNS_COUNT
#define DEF_TUNNEL_DNS_COUNT 40960
#endif

typedef struct {
   char domain[TUNNEL_DNS_DOMAIN_LEN];
   char addr[TUNNEL_DNS_ADDR_LEN];
   int date;
   dns_query_callback cb;
   void *opaque;
} dns_entry_t;

typedef struct {
   dict_t *entry_dict;          /* for speed up query, in aux */
   stm_t *domain_stm;
} dns_t;

static dns_t g_dns;

static int _dns_mthrd_func(void *opaque);

static void
_domain_stm_finalizer(void *ptr, void *ud) {
   mm_free(ptr);
}

static dns_t* _dns(void) {
   if (g_dns.entry_dict == NULL) {
      g_dns.entry_dict = dict_create(DEF_TUNNEL_DNS_COUNT);
      g_dns.domain_stm = stm_create("dns_domain_cache", _domain_stm_finalizer, NULL);
      mthrd_after(MTHRD_AUX, _dns_mthrd_func, &g_dns, 0);
   }
   return &g_dns;
}

static int _dns_date() {
   return (int)(mtime_current() >> 20);
}

static dns_entry_t*
_dns_entry_create(const char *domain, int domain_len, const char *addr, int addr_len) {
   dns_t *dns = _dns();
   dns_entry_t *e = mm_malloc(sizeof(*e));
   strncpy(e->domain, domain, domain_len);
   strncpy(e->addr, addr, _MIN_OF(TUNNEL_DNS_ADDR_LEN, addr_len));
   e->date = _dns_date();
   dict_set(dns->entry_dict, domain, domain_len, e);
   _err("add dns entry [%s, %s], %d\n", e->domain, e->addr, e->date);
   return e;
}

static void
_dns_entry_destroy(dns_entry_t *e) {
   dns_t *dns = _dns();
   dict_remove(dns->entry_dict, e->domain, strlen(e->domain));
   mm_free(e);
}

/* description: check valid ip addr */
static int
_valid_ip_addr(const char *addr, int addr_len) {
   int isValid = 1;
   for (int i=0; i<addr_len; i++) {
      if (addr[i]!='.' && (addr[i]<'0' || addr[i]>'9')) {
         isValid = 0;
         break;
      }
   }
   return addr_len<=0 ? 0 : isValid;
}

/* description: query it from DNS server */
static int
_dns_addr_by_name(const char *domain, int domain_len, char *addr, int addr_len) {
#if 1
   int error = 0;
   struct sockaddr_in sa;
   struct addrinfo *result = NULL;

   sa.sin_family = AF_INET;
   error = getaddrinfo(domain, "http", NULL, &result);
   if (error != 0) {
      _err("Fail to get addr info: [%s] of %s\n", gai_strerror(error));
      goto fail;
   }
    
   memcpy(&sa, result->ai_addr, sizeof(sa));

   error = getnameinfo((struct sockaddr*)&sa, sizeof(sa), addr, addr_len,
                       NULL, 0, NI_NUMERICHOST);
   if (error != 0) {
      _err("Fail to get host name info: %d\n", error);
      goto fail;
   }

  fail:
   if ( result ) {
      freeaddrinfo(result);
   }
#else
   struct addrinfo hints, *res, *res0;
   int error;

   memset(&hints, 0, sizeof(hints));
   hints.ai_family = AF_INET;//PF_UNSPEC;
   hints.ai_socktype = SOCK_STREAM;
   error = getaddrinfo(domain, "http", &hints, &res0);
   if (error) {
      _err("Fail to get addr info: %s", gai_strerror(error));
      return 0;
   }
   for (res = res0; res; res = res->ai_next) {
      struct sockaddr_in *s = (struct sockaddr_in*)res->ai_addr->sa_data;
      strncpy(addr, inet_ntoa(s->sin_addr), addr_len);
      break;
   }
   freeaddrinfo(res0);
#endif
   return _valid_ip_addr(addr, strlen(addr));
}

/* description: 2 hour to expire */
static int
_dns_entry_is_expired(dns_entry_t *e) {
   if (e) {
      int date = _dns_date();
      if ((date - e->date) < 7200) {
         return 0;
      }
      _dns_entry_destroy(e);
   }
   return 1;
}

int
_dns_mthrd_func(void *opaque) {
   dns_t *dns = (dns_t*)opaque;

   if (stm_count(dns->domain_stm) <= 0) {
      mtime_sleep(1);
   }
   else {

      dns_entry_t *oe = stm_popf(dns->domain_stm);
      int domain_len = strlen(oe->domain);

      if ( _valid_ip_addr(oe->domain, domain_len) ) {
         strncpy(oe->addr, oe->domain, domain_len);
         if (oe->cb) {
            oe->cb(oe->addr, strlen(oe->addr), oe->opaque);
         }
      }
      else {
         dns_entry_t *ne = dict_get(dns->entry_dict, oe->domain, domain_len);
         if ( !_dns_entry_is_expired(ne) ) {
            strcpy(oe->addr, ne->addr);
            if (oe->cb) {
               oe->cb(oe->addr, strlen(oe->addr), oe->opaque);
            }
         }
         else {
            char dn[TUNNEL_DNS_DOMAIN_LEN] = {0};
            strncpy(dn, oe->domain, _MIN_OF(TUNNEL_DNS_DOMAIN_LEN, domain_len));

            int addr_len = TUNNEL_DNS_ADDR_LEN;
            int found_addr = 0;

            for (int i=0; i<8; i++) {
               int dlen = strlen(dn);

               if (_dns_addr_by_name(dn, dlen, oe->addr, addr_len) > 0) {
                  _dns_entry_create(oe->domain, domain_len, oe->addr, addr_len);
                  found_addr = 1;
                  break;
               }

               strncpy(dn, oe->addr, addr_len);
               memset(oe->addr, 0, addr_len);
            }

            if (oe->cb) {
               if (found_addr) {
                  oe->cb(oe->addr, strlen(oe->addr), oe->opaque);
               }
               else {
                  oe->cb(NULL, 0, oe->opaque);
               }
            }
         }
      }

      _domain_stm_finalizer(oe, NULL);
   }

   return 1;
}

/* Public Interfaces 
 */

void
dns_query_domain(const char *domain, int domain_len, dns_query_callback cb, void *opaque) {
   if (domain && domain_len>0 && cb) {
      dns_t *dns = _dns();
      dns_entry_t *e = (dns_entry_t*)mm_malloc(sizeof(*e));

      strncpy(e->domain, domain, _MIN_OF(domain_len, TUNNEL_DNS_DOMAIN_LEN));
      e->date = _dns_date();
      e->cb = cb;
      e->opaque = opaque;

      stm_pushl(dns->domain_stm, e);
   }
}

#if 0
void
dns_save() {
   dns_t *dns = _dns();
   FILE *fp = fopen(dns->entry_path, "wb");
   if ( fp ) {
      dict_foreach(dns->entry_dict, _dns_enumerate_cb, fp);
      fclose(fp);
      _info("save dns record %d\n", dict_count(dns->entry_dict));
   }
}

void dns_restore(const char *entry_path) {
   dns_t *dns = _dns();

   if (/*entry_path*/0) {
      strcpy(dns->entry_path, entry_path);
      
      unsigned long flength = 0;
      const char *dns_content = misc_read_file(entry_path, &flength);
      if (dns_content) {
         str_t *hstr = str_clone_cstr(dns_content, flength);
         str_t *entries = str_split(hstr, "\n", 0);
         if (entries) {
            str_foreach(it, entries) {
               str_t *se = str_split(it, ":", 0);
               dns_entry_t *de = mm_malloc(sizeof(*de));

               int domain_len = str_len(se);

               strncpy(de->domain, str_cstr(se), domain_len); se=str_next(se);
               strncpy(de->addr, str_cstr(se), str_len(se)); se=str_next(se);
               de->date = atoi(str_cstr(se));

               dict_set(dns->entry_dict, de->domain, domain_len, de);
            }

            _info("restore dns record %d in %d\n",
                  dict_count(dns->entry_dict), (int)(mtime_current()>>20));
         }
         else {
            _err("fail to split file content of %s!\n", entry_path);
         }
         str_destroy(hstr);
         mm_free((void*)dns_content);
      }
   }
}
#endif
