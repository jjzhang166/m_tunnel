/* 
 * Copyright (c) 2015 lalawue
 * 
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the MIT license. See LICENSE for details.
 */

#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "plat_lock.h"
#include "m_mem.h"
#include "m_list.h"
#include "m_stm.h"

struct s_stm {
   lock_t lock;
   lst_t *data_lst;
   stm_finalizer finalizer;
   void *ud;
   char name[1];
};

typedef struct {
   lock_t lock;
   int init;
   lst_t *stm_lst;
} global_stm_t;

static global_stm_t _g_stm;

void stm_init(void) {
   global_stm_t *gs = &_g_stm;
   if ( !gs->init ) {
      gs->init = 1;
      gs->stm_lst = lst_create();
   }
}

void stm_fini(void) {
   global_stm_t *gs = &_g_stm;
   if (gs->init) {
      while (lst_count(gs->stm_lst) > 0) {
         stm_t *s = (stm_t*)lst_popf(gs->stm_lst);
         stm_clear(s);
         lst_destroy(s->data_lst);
         mm_free(s);
      }
      lst_destroy(gs->stm_lst);
      gs->init = 0;
   }
}

stm_t*
stm_create(const char *name, stm_finalizer f, void *ud) {
   if (name == NULL) return NULL;
   if ( !stm_retrive(name) ) {
      global_stm_t *gs = &_g_stm;
      stm_t *s = (stm_t*)mm_malloc(sizeof(*s) + (unsigned)strlen(name));
      strcpy(s->name, name);
      s->finalizer = f;
      s->ud = ud;
      s->data_lst = lst_create();

      _lock(gs->lock);
      lst_pushl(gs->stm_lst, s);
      _unlock(gs->lock);
      return s;
   }
   return NULL;
}

stm_t*
stm_retrive(const char *name) {
   global_stm_t *gs = &_g_stm;
   _lock(gs->lock);
   lst_foreach(its, gs->stm_lst) {
      stm_t *ss = (stm_t*)lst_iter_data(its);
      if (strcmp(ss->name, name) == 0) {
         _unlock(gs->lock);
         return ss;
      }
   }
   _unlock(gs->lock);
   return NULL;
}

static inline void
_dumb_finalizer(void *ptr, void *ud) {
}

void stm_clear(stm_t *s) {
   if ( s ) {
      _lock(s->lock);
      stm_finalizer f = s->finalizer ? s->finalizer : _dumb_finalizer;
      while (lst_count(s->data_lst) > 0) {
         void *data = lst_popf(s->data_lst);
         f(data, s->ud);
      }
      _unlock(s->lock);
   }
}

int stm_count(stm_t *s) {
   return s ? lst_count(s->data_lst) : -1;
}

int stm_pushf(stm_t *s, void *data) {
   if ( s ) {
      _lock(s->lock);
      lst_pushf(s->data_lst, data);
      _unlock(s->lock);
      return 1;
   }
   return 0;
}

int stm_pushl(stm_t *s, void *data) {
   if ( s ) {
      _lock(s->lock);
      lst_pushl(s->data_lst, data);
      _unlock(s->lock);
      return 1;
   }
   return 0;
}

void* stm_popf(stm_t *s) {
   void *data = NULL;
   if ( s ) {
      _lock(s->lock);
      data = lst_popf(s->data_lst);
      _unlock(s->lock);
   }
   return data;
}

void* stm_popl(stm_t *s) {
   void *data = NULL;
   if ( s ) {
      _lock(s->lock);
      data = lst_popl(s->data_lst);
      _unlock(s->lock);
   }
   return data;
}

int stm_total(void) {
   global_stm_t *gs = &_g_stm;
   return lst_count(gs->stm_lst);
}

#ifdef STM_TEST

#include <pthread.h>
#include <unistd.h>
#include <assert.h>

#define PTH_COUNT 4

//#define TEST_LOCKER

#ifdef TEST_LOCKER
struct s_lock {
   lock_t lock;
};

static struct s_lock g_lock;

typedef struct {
   int val;
} val_t;

static int g_addVal;
static int g_subVal;

/* test locker */
void* pth_func(void *param) {
   struct s_lock *s = &g_lock;
   val_t *v = (val_t*)param;
   while (v->val) {
      _lock(s->lock);
      g_addVal += (v->val - 3);
      g_subVal -= (v->val - 3);
      if (g_addVal != -g_subVal) {
         printf("[%d] [%d, %d]\n", v->val, g_addVal, g_subVal);
      }
      _unlock(s->lock);
   }
   return NULL;
}
#else

typedef struct {
   int addVal;
   int subVal;
} twin_val_t;

static int g_exit;

void _finalizer(void *ptr, void *ud) {
   char *str = (char*)ud;
   twin_val_t *t = (twin_val_t*)ptr;
   printf("finalize %s, %d:%d\n", str, t->addVal, t->subVal);
   mm_free(ptr);
}

uint64_t _count;

void* pth_func(void *param) {
   int idx = *((int*)param);
   stm_t *s = stm_retrive("stm");
   if ( s ) {
      twin_val_t *t = NULL;
      if (idx == 0) {
         while (!g_exit && (t = stm_popf(s))) {
            if (t->addVal != -t->subVal) {
               printf("%d:%d\n", t->addVal, t->subVal);
            }
            stm_pushl(s, t);
            _count++;
         }
      }
      else {
         while (!g_exit && (t = stm_popf(s))) {
            int k = rand() & 0xff;
            t->addVal += k;
            t->subVal -= k;
            stm_pushl(s, t);
            usleep(k >> 2);
         }
      }
   }
   else {
      printf("fail to retrieve !\n");
   }
   printf("exit pthread %d, %lld\n", idx, _count);
   return NULL;
}
#endif  /* TEST_LOCKER */

int main(int argc, char *argv[]) {
   int i;
   pthread_t pth[PTH_COUNT];
#ifdef TEST_LOCKER
   val_t vals[PTH_COUNT];
   int val_array[PTH_COUNT] = {1, 2, 4, 5};

   struct s_lock *s = &g_lock;
   LOCKER_INIT(s->lock);

   for (i=0; i<PTH_COUNT; i++) {
      vals[i].val = val_array[i];
   }

   for (i=0; i<PTH_COUNT; i++) {
      pthread_create(&pth[i], NULL, pth_func, &vals[i]);
   }

   usleep(5000000);

   for (i=0; i<PTH_COUNT; i++) {
      vals[i].val = 0;
      pthread_join(pth[i], NULL);
   }
   LOCKER_FINI(s->lock);
#else
   srand(time(NULL));
   stm_init();

   stm_t *s = stm_create("stm", _finalizer, "stm222"); 
   for (i=0; i<PTH_COUNT * 2; i++) {
      twin_val_t *t = (twin_val_t*)mm_malloc(sizeof(*t));
      t->addVal = i+1;
      t->subVal = -i-1;
      stm_pushl(s, t);
   }

   usleep(100);

   int val_array[PTH_COUNT];
   for (i=0; i<PTH_COUNT; i++) {
      val_array[i] = i;
      pthread_create(&pth[i], NULL, pth_func, &val_array[i]);
   }

   usleep(5000000);

   g_exit = 1;

   for (i=0; i<PTH_COUNT; i++) {
      pthread_join(pth[i], NULL);
   }

   stm_fini();
#endif

   return 0;
}
#endif
