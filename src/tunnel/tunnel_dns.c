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
#include "m_debug.h"

#include "plat_time.h"

#include "utils_str.h"
#include "utils_misc.h"

#include "tunnel_dns.h"

#include "plat_lock.h"
#include "plat_thread.h"

#include <assert.h>

#define _err(...) _mlog("dsn", D_ERROR, __VA_ARGS__)
#define _info(...) _mlog("dns", D_INFO, __VA_ARGS__)

typedef struct {
   char domain[TUNNEL_DNS_DOMAIN_LEN];
   char addr[TUNNEL_DNS_ADDR_LEN];
   int date;
} dns_entry_t;

typedef struct {
   char domain[TUNNEL_DNS_DOMAIN_LEN];
   int domain_len;
} block_entry_t;

typedef struct {
   char entry_path[TUNNEL_DNS_DOMAIN_LEN];
   char block_path[TUNNEL_DNS_DOMAIN_LEN];
   dict_t *entry_dict;          /* for speed up query */
   lst_t *block_lst;            /* for remote DNS */
   lock_t lock;
} dns_t;

static dns_t g_dns;

static dns_t* _dns(void) {
   if (g_dns.entry_dict == NULL) {
      g_dns.entry_dict = dict_create(8196);
      g_dns.block_lst = lst_create();
   }
   return &g_dns;
}

static dns_entry_t*
_dns_entry_create(const char *domain, int domain_len, const char *addr, int addr_len) {
   dns_t *dns = _dns();
   dns_entry_t *e = mm_malloc(sizeof(*e));
   strncpy(e->domain, domain, domain_len);
   strncpy(e->addr, addr, _MIN_OF(TUNNEL_DNS_ADDR_LEN, addr_len));
   e->date = (int)(mtime_current() >> 20);
   dict_set(dns->entry_dict, domain, domain_len, e);
   _err("add dns entry [%s, %s]\n", misc_fix_str_1024(domain, domain_len), addr);
   return e;
}

#if 0
static void
_dns_entry_destroy(dns_entry_t *e) {
   dns_t *dns = _dns();
   lst_remove(dns->entry_lst, e->node);
   mm_free(e);
}
#endif

/* description: find domain entry in list
 */
static dns_entry_t*
_dns_find_domain(const char *domain, int domain_len) {
   dns_t *dns = _dns();
   return dict_get(dns->entry_dict, domain, domain_len);
}

/* description: check valid ip addr
 */
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

/* description: query it from DNS server
 */
static int
_dns_addr_by_name(const char *domain, int domain_len, char *addr, int addr_len) {
#if 1
   int error = 0;
   struct sockaddr_in sa;
   struct addrinfo *result = NULL;

   sa.sin_family = AF_INET;
   error = getaddrinfo(domain, "http", NULL, &result);
   if (error != 0) {
      _err("Fail to get addr info: [%s] of %s\n", gai_strerror(error), misc_fix_str_1024(domain, domain_len));
      goto fail;
   }
    
   memcpy(&sa, result->ai_addr, sizeof(sa));

   error = getnameinfo((struct sockaddr*)&sa, sizeof(sa), addr, addr_len,
                       NULL, 0, NI_NUMERICHOST);
   if (error != 0) {
      _err("Fail to get host name info: %d of %s\n", error, misc_fix_str_1024(domain, domain_len));
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

/* Public Interfaces 
 *
 */

static int
_is_sub_domain(const char *sub_domain, int sub_len, const char *domain, int len) {
   if (sub_len < len) {
      return 0;
   }

   int si = sub_len - 1;
   int di = len - 1;
   for (; di>=0; di--, si--) {
      if (domain[di] != sub_domain[si]) {
         return 0;
      }
   }

   return 1;
}

int
dns_domain_is_block(const char *domain, int domain_len) {
   if (domain && domain_len>0) {
      dns_t *dns = _dns();
      //_err("check domain <%s>\n", misc_fix_str_1024(domain, domain_len));
      lst_foreach(it, dns->block_lst) {
         block_entry_t *e = lst_iter_data(it);
         if ( _is_sub_domain(domain, domain_len, e->domain, e->domain_len) ) {
            //_err("is sub domain %s\n", e->domain);
            return 1;
         }
      }
   }
   return 0;
}

int
dns_domain_query_ip(const char *domain, int domain_len, char *addr, int addr_len) {
   int ret = 0;

   if (domain && addr) {
      if ( _valid_ip_addr(domain, domain_len) ) {
         strncpy(addr, domain, domain_len);
         return 1;
      }
      else {
         dns_entry_t *e = _dns_find_domain(domain, domain_len);
         if ( e ) {
            strcpy(addr, e->addr);
            return 1;
         }

         _err("dns [%s]\n", misc_fix_str_1024(domain, domain_len));

         char dn[1024] = {0};
         strncpy(dn, domain, _MIN_OF(1024, domain_len));

         for (int i=0; i<8; i++) {
            int dlen = strlen(dn);

            if (_dns_addr_by_name(dn, dlen, addr, addr_len) > 0) {
               _dns_entry_create(domain, domain_len, addr, addr_len);
               ret = 1;
               break;
            }

            strncpy(dn, addr, addr_len);
            memset(addr, 0, addr_len);
         }

         if (ret <= 0) {
            _err("fail to dns [%s]\n", domain);
         }
      }
   }
   return ret;
}

int
dns_domain_query_ip_local(const char *domain, int domain_len, char *addr, int addr_len) {
   if (domain && addr) {
      if ( _valid_ip_addr(domain, domain_len) ) {
         strncpy(addr, domain, domain_len);
         return 1;
      }
      else {
         dns_entry_t *e = _dns_find_domain(domain, domain_len);
         if ( e ) {
            strcpy(addr, e->addr);
            return 1;
         }
      }
   }
   return 0;
}

int dns_domain_set_ip_local(
   const char *domain, int domain_len, char *addr, int addr_len) {
   if (domain && addr) {
      if (dns_domain_query_ip_local(domain, domain_len, addr, addr_len) <= 0) {
         _dns_entry_create(domain, domain_len, addr, addr_len);
         return 1;
      }
   }
   return 0;
}

static void
_dns_enumerate_cb(void *opaque, const char *key, int keylen, void *value, int *stop) {
   FILE *fp = opaque;
   dns_entry_t *e = value;
   fprintf(fp, "%s:%s:%d\n", e->domain, e->addr, e->date);
}

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

void dns_restore(const char *entry_path, const char *block_path) {
   dns_t *dns = _dns();

   if (entry_path) {
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

   if (block_path) {
      _info("restore local blocks\n");
      strcpy(dns->block_path, block_path);
   
      unsigned long flength = 0;
      const char *block_content = misc_read_file(block_path, &flength);
      if (block_content) {
         str_t *hstr = str_clone_cstr(block_content, flength);
         str_t *entries = str_split(hstr, "\n", 0);
         if (entries) {
            str_foreach(it, entries) {
               block_entry_t *be = mm_malloc(sizeof(*be));;
               be->domain_len = str_len(it);
               strncpy(be->domain, str_cstr(it), be->domain_len);
               //_err("load block <%s>, %d\n", misc_fix_str_1024(be->domain, be->domain_len), be->domain_len);
               lst_pushl(dns->block_lst, be);
            }
         }
         str_destroy(hstr);
         mm_free((void*)block_content);
      }
   }
}
