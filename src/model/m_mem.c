/* 
 * Copyright (c) 2015 lalawue
 * 
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the MIT license. See LICENSE for details.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "plat_lock.h"
#include "m_mem.h"


#define _log(...) printf(__VA_ARGS__)

#define _MAGIC_MARK 0xF00D

typedef struct s_mem {
   struct s_mem *prev;         /* head prev == NULL */
   struct s_mem *next;         /* last next == NULL */
   char *fname;
   unsigned long size;
   unsigned short line;
   unsigned short magic;
} mem_t;

typedef struct s_memhead {
   lock_t lock;
   unsigned count;
   unsigned long size;
   mem_t *head;
} memhead_t;

static memhead_t g_mh;

#define _MEM_TO_PTR(M) ((uint8_t*)(M) + sizeof(mem_t))
#define _PTR_TO_MEM(P) ((mem_t*)((uint8_t*)(P) - sizeof(mem_t)))

void* mm_malloc_ex(unsigned long sz, char *fname, int line) {
   memhead_t *mh = &g_mh;
   mem_t *m = (mem_t*)malloc(sz + sizeof(mem_t));
   if ( m ) {
      memset(m, 0, sizeof(*m) + sz);
      m->fname = fname;
      m->line = (unsigned short)line;
      m->size = sz + sizeof(*m);
      m->magic = _MAGIC_MARK;

      _lock(mh->lock);
      if ( mh->head ) {
         m->next = mh->head;
         mh->head->prev = m;
      }
      mh->head = m;
      mh->count++;
      mh->size += m->size;
      _unlock(mh->lock);
      return _MEM_TO_PTR(m);
   }
   assert(0);
   return NULL;
}

int mm_has(void *p) {
   mem_t *m = _PTR_TO_MEM(p);
   mem_t *h = g_mh.head;
   while ( h ) {
      if (h == m) {
         return 1;
      }
      h = h->next;
   }
   _log("[mem] invalid %p, %d, %s\n", m, m->line, m->fname);
   return 0;
}

unsigned long mm_free_ex(void *p, char *fname, int line) {
   memhead_t *mh = &g_mh;
   _lock(mh->lock); 
   if (p && mh->count>0) {
      unsigned long sz = 0;
      mem_t *m = _PTR_TO_MEM(p);
        
      if (m->magic != _MAGIC_MARK) {
         _log("[mem] (%s:%d), %lu\n", m->fname, m->line, m->size);
         assert(0);
      }

      if (mh->head == m) mh->head = m->next;
      if (m->prev) m->prev->next = m->next;
      if (m->next) m->next->prev = m->prev;
      mh->count--;
      mh->size -= m->size;
      sz = m->size - sizeof(*m);
      free(m);
      _unlock(mh->lock);
      return sz;
   }
   assert(0);
   return 0;
}

void* mm_realloc_ex(void *p, unsigned long sz, char *fname, int line) {
   memhead_t *mh = &g_mh;
   if ( p ) {
      mem_t *m = _PTR_TO_MEM(p);
      mem_t *nm = (mem_t*)realloc(m, sz + sizeof(*m));
      if (nm == NULL) { return NULL; }

      _lock(mh->lock);
      if (mh->head == m) { mh->head = nm; }
      mh->size = mh->size - nm->size + sz + sizeof(*nm);
      _unlock(mh->lock);

      if (nm->prev) nm->prev->next = nm;
      if (nm->next) nm->next->prev = nm;

      nm->fname = fname;
      nm->line = (unsigned short)line;
      nm->size = sz + sizeof(*nm);
      nm->magic = _MAGIC_MARK;
      return _MEM_TO_PTR(nm);
   }
   return mm_malloc_ex(sz, fname, line);
}

typedef struct {
   char *fname;
   size_t size;
} mrec_t;

static int
_rec_compare(const void *v1, const void *v2) {
   mrec_t *m1=(mrec_t*)v1, *m2=(mrec_t*)v2;
   return (m1->size < m2->size) ? 1 : -1;
}

void mm_report(int brief_level) {
   memhead_t *mh = &g_mh;
   _lock(mh->lock);
   if (mh->head) {
      mem_t *m = mh->head;
      _log("[mem] ---- active %d, size %luKb ----\n", mh->count, mh->size>>10);
      if (brief_level == 2) {
         int i = mh->count;
         while (i-- > 0) {
            _log("[mem] (%d:%s), %lu bytes\n", m->line, m->fname, m->size);
            m = m->next;
         };
      }
      else if (brief_level == 1) {
         mrec_t mrec[128];
         memset(mrec, 0, 128*sizeof(mrec_t));
         int i, count=mh->count, top = 0;
         while (count-- > 0) {
            mrec_t *mt = &mrec[top];
            for (i=0; i<top; i++) {
               if (mrec[i].fname == m->fname) {
                  mt = &mrec[i]; mt->size += m->size;
                  goto m_next;
               }
            }
            mt->fname=m->fname;  mt->size=m->size;  top++;
           m_next: m = m->next;
         }
         qsort(mrec, top, sizeof(mrec_t), _rec_compare);
         for (i=0; i<top; i++) {
            mrec_t *mt = &mrec[i];
            _log("[mem] %s, %luKb\n", mt->fname, mt->size>>10);
         }
      }
      else {
         goto report_end;
      }
      _log("[mem] ---- end report ----\n");
   }
   else {
      _log("[mem] no more active\n");
   }
  report_end:
   _unlock(mh->lock);
}
