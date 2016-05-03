/* 
 * Copyright (c) 2015 lalawue
 * 
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the MIT license. See LICENSE for details.
 */

#include <string.h>
#include <assert.h>

#include <stdint.h>
#include "m_dict.h"
#include "m_list.h"
#include "m_mem.h"

typedef struct s_dict_kv {
   struct s_dict_kv *next;
   lst_node_t *node;            /* node of list */
   uint32_t hash;
   void *value;
   int keylen;
   char *key;
} dict_kv_t;

struct s_dict {
   int count;
   int capacity;
   lst_t *lst;
   dict_kv_t **data;
};

dict_t*
dict_create(int capacity) {
   if (capacity > 0) {
      dict_t *d = (dict_t*)mm_malloc(sizeof(*d) + capacity * sizeof(dict_kv_t*));
      if (d) {
         d->capacity = capacity;
         d->data = (dict_kv_t**)((unsigned char*)d + sizeof(*d));
         d->lst = lst_create();
         return d;
      }
   }
   return NULL;
}

void
dict_destroy(dict_t *d) {
   if (d) {
      lst_destroy(d->lst);
      mm_free(d);
   }
}

int
dict_count(dict_t *d) {
   if (d) {
      return d->count;
   }
   return -1;
}

static uint32_t
_key_hash(const char *name, size_t len) {
   uint32_t h = (uint32_t)len;
   for (int i=0; i<len; i++) {
      h = h ^ ((h<<5)+(h>>2)+(uint32_t)name[i]);
   }
   return h;
}

static dict_kv_t*
_dict_get_kv(dict_t *d, const char *key, int keylen) {
   uint32_t hash = _key_hash(key, keylen);
   dict_kv_t *kv = d->data[hash % d->capacity];
   while (kv) {
      if ((kv->hash==hash) && (kv->keylen==keylen) && (strncmp(kv->key, key, keylen)==0)) {
         return kv;
      }
      kv = kv->next;
   }
   return NULL;
}

void*
dict_get(dict_t *d, const char *key, int keylen) {
   if  (d && key && keylen>0) {
      dict_kv_t *kv = _dict_get_kv(d, key, keylen);
      if (kv) {
         return kv->value;
      }
   }
   return NULL;
}

int
dict_set(dict_t *d, const char *key, int keylen, void *data) {
   if (d && key && keylen>0 && data) {
      uint32_t hash = _key_hash(key, keylen);
      uint32_t h = hash % d->capacity;

      dict_kv_t *kv = (dict_kv_t*)mm_malloc(sizeof(*kv) + keylen + 1);
      if (kv) {
         kv->next = d->data[h];
         d->data[h] = kv;

         kv->node = lst_pushl(d->lst, kv);
         kv->hash = hash;
         kv->value = data;
         kv->keylen = keylen;

         kv->key = (char*)(((unsigned char*)kv) + sizeof(*kv));
         strncpy(kv->key, key, keylen);
         d->count++;
         return 1;
      }
   }
   return 0;
}

/* FIXME: remove all key/keylen data */
void* dict_remove(dict_t *d, const char *key, int keylen) {
   if (d && key && keylen) {
      dict_kv_t *rkv = _dict_get_kv(d, key, keylen);
      if (rkv) {
         void *value = rkv->value;

         uint32_t h = rkv->hash % d->capacity;
         dict_kv_t *kv = d->data[h];
         if (kv == rkv) {
            d->data[h] = kv->next;
         }
         else {
            while (kv->next != rkv) {
               kv = kv->next;
            }
            kv->next = rkv->next;
         }
         lst_remove(d->lst, rkv->node);

         //mm_free(rkv->key);
         mm_free(rkv);
         d->count--;
         return value;
      }
   }
   return NULL;
}

void
dict_foreach(dict_t *d, dict_enumerate_callback cb, void *opaque) {
   if (d && cb) {
      int stop = 0;
      lst_foreach(it, d->lst) {
         dict_kv_t *e = lst_iter_data(it);
         cb(opaque, e->key, e->keylen, e->value, &stop);
         if (stop) {
            break;
         }
      }
   }
}
