/* 
 * Copyright (c) 2015 lalawue
 * 
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the MIT license. See LICENSE for details.
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "m_mem.h"
#include "m_list.h"
#include "m_debug.h"
#include "plat_time.h"
#include "plat_lock.h"
#include "plat_thread.h"

#define _err(...)  _mlog("thrd", D_ERROR, __VA_ARGS__)
#define _log(...)  _mlog("thrd", D_INFO, __VA_ARGS__)

#define MTHRD_TH_COUNT (MTHRD_AUX + 1)

#if defined(_WIN32)
#include <windows.h>
#include <process.h>
typedef HANDLE thread_t;
#define THRD_RET_TYPE unsigned __stdcall
#define THRD_PARAM_TYPE void*

#else
#include <pthread.h>
#if defined(__APPLE__)
#include <dispatch/dispatch.h>
#endif  /* __APPLE__ */

typedef pthread_t thread_t;
#define THRD_RET_TYPE void*
#define THRD_PARAM_TYPE void*
#endif

typedef struct {
   mthread_func func;
   void *ud;
   int active;
   int count;
   int milli_second;
} mfunc_t;

typedef struct {
   int th_type;
   int running;
   thread_t thid;

   lst_t *ready_lst;            /* func to running */
   lst_t *free_lst;             /* func is suspend */

   lock_t lock_free;            /* lock free list */
   int have_new;                /* active func in free list  */

   int64_t last_ms;             /* only use in apple */

   int suspend;
} mthrd_t;

#ifdef __APPLE__
dispatch_queue_t _m_queid[MTHRD_TH_COUNT];
#endif

typedef struct {
   int init;
   int mode;
   mthrd_t mthrd_ary[MTHRD_TH_COUNT];
} global_mthrd_t;

static global_mthrd_t _g_mth;

static THRD_RET_TYPE _mthrd_wrapper_func(THRD_PARAM_TYPE param);

THRD_RET_TYPE
_mthrd_wrapper_func(THRD_PARAM_TYPE param)
{
   global_mthrd_t *gm = &_g_mth;
   mthrd_t *m = (mthrd_t*)param;

   while (m->running) {
      mfunc_t *f = NULL;

      if ( !m->suspend ) {
         if (lst_count(m->ready_lst) > 0) {
            lst_foreach(itr, m->ready_lst) {
               f = (mfunc_t*)lst_iter_data(itr);
               if (--f->count <= 0) {
                  f->active = f->func(f->ud);
                  if ( f->active ) {
                     f->count = f->milli_second;
                  } else {
                     lst_iter_remove(itr);

                     _lock(m->lock_free);
                     lst_pushl(m->free_lst, f);
                     _unlock(m->lock_free);
                  }
               }
            }
         }

         if ( m->have_new ) {
            _lock(m->lock_free);
            lst_foreach(itf, m->free_lst) {
               f = (mfunc_t*)lst_iter_data(itf);
               if ( f->active ) {
                  lst_pushl(m->ready_lst, lst_iter_remove(itf));
               }
            }
            m->have_new = 0;
            _unlock(m->lock_free);
         }
      }

      if (gm->mode == MTHRD_MODE_POWER_HIGH) {
         if (lst_count(m->ready_lst) <= 0) {
            mtime_sleep(1);
         }
      } else {
#ifdef __APPLE__ /* POWER_LOW */
         if (m->running == 1) {
            int64_t cur_ms = mtime_current();
            dispatch_time_t after = dispatch_time(DISPATCH_TIME_NOW, NSEC_PER_MSEC - (cur_ms - m->last_ms)*1000);
            m->last_ms = cur_ms;
            dispatch_after(after, _m_queid[m->th_type], ^{ _mthrd_wrapper_func(m); });
            return NULL;
         } else {
            break;
         }
#else
         mtime_sleep(1);
#endif
      }
   } /* while */
   m->running = 2; /* exit state 2 */

#ifdef _WIN32
   _endthreadex(0);
#elif defined(__APPLE__)
   if (gm->mode == MTHRD_MODE_POWER_LOW) {
      return NULL;
   } else {
      pthread_exit(NULL);
   }
#else
   pthread_exit(NULL);
#endif
   return NULL;
}

int mthrd_init(int mode) {
   global_mthrd_t *gm = &_g_mth;
   if ( !gm->init ) {
      gm->mode = (mode & 1);

      for (int i=0; i<MTHRD_TH_COUNT; i++) {
         mthrd_t *m = &gm->mthrd_ary[i];
         memset(m, 0, sizeof(*m));

         m->th_type = i;
         m->running = 1;        /* running state 1 */

         m->ready_lst = lst_create();
         m->free_lst = lst_create();

#if defined(_WIN32)
         unsigned threadID;
         m->thid = (HANDLE)_beginthreadex(NULL,0,&_mthrd_wrapper_func,(void*)m,0,&threadID);
         _log("create win32 thread %p\n", m->thid);
#elif defined(__APPLE__)
         if (gm->mode == MTHRD_MODE_POWER_LOW) {
            dispatch_queue_t _thread[MTHRD_TH_COUNT] = {
               dispatch_get_main_queue(),
               dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_LOW, 0),
            };
            m->last_ms = mtime_current();
            dispatch_time_t after = dispatch_time(DISPATCH_TIME_NOW, 0.001*NSEC_PER_SEC);
            dispatch_after(after, _thread[i] , ^{ _mthrd_wrapper_func(m); });
            _log("create ios/osx dispatcher %p\n", (_m_queid[i] = _thread[i]));
            continue;
         } else {
            pthread_create(&m->thid, NULL, _mthrd_wrapper_func, m);
            _log("create pthread %p\n", m->thid);
         }
#else
         pthread_create(&m->thid, NULL, _mthrd_wrapper_func, m);
         _log("create pthread %p\n", &m->thid);
#endif  /* _WIN32 */
      }
      gm->init = 1;
      return 1;
   }
   _err("fail to init\n");
   assert(0);
   return 0;
}

void mthrd_fini(void) {
   global_mthrd_t *gm = &_g_mth;   
   if (gm->init) {
      for (int i=0; i<MTHRD_TH_COUNT; i++) {
         mthrd_t *m = &gm->mthrd_ary[i];

         /* first exit, then testing exit state */
         m->running = 0;
         while (m->running != 2) {
            mtime_sleep(1);
         }

         _lock(m->lock_free);

         while (lst_count(m->ready_lst) > 0) {
            mm_free(lst_popf(m->ready_lst));
         }
         lst_destroy(m->ready_lst);

         while (lst_count(m->free_lst) > 0) {
            mm_free(lst_popf(m->free_lst));
         }
         lst_destroy(m->free_lst);

         _unlock(m->lock_free);

#if defined(_WIN32)
         CloseHandle(m->thid);
#elif defined(__APPLE__)
         if (gm->mode == MTHRD_MODE_POWER_HIGH) {
            pthread_detach(m->thid);
         }
#else
         pthread_detach(m->thid);
#endif
      }
      memset(gm, 0, sizeof(*gm));
   }
}

int
mthrd_after(
   int th_type, mthread_func func, void *ud, int milli_second)
{
   global_mthrd_t *gm = &_g_mth;
   if ((th_type < MTHRD_TH_COUNT) && func && (milli_second>=0)) {
      mthrd_t *m = &gm->mthrd_ary[th_type];
      mfunc_t *f = NULL;

      _lock(m->lock_free);
      lst_foreach(itf, m->free_lst) {
         f = (mfunc_t*)lst_iter_data(itf);
         if ( !f->active ) {
            goto assign_func;
         }
      }
      f = (mfunc_t*)mm_malloc(sizeof(*f));
      lst_pushl(m->free_lst, f);

     assign_func:
      memset(f, 0, sizeof(*f));
      f->func = func;
      f->ud = ud;
      f->active = 1;
      f->milli_second = milli_second;
      f->count = milli_second;

      m->have_new = 1;
      _unlock(m->lock_free);
      return 1;
   }
   return 0;
}

void mthrd_suspend(int th_type) {
   if (th_type < MTHRD_TH_COUNT) {
      mthrd_t *m = &_g_mth.mthrd_ary[th_type];
      m->suspend = 1;
   }
}

void mthrd_resume(int th_type) {
   if (th_type < MTHRD_TH_COUNT) {
      mthrd_t *m = &_g_mth.mthrd_ary[th_type];
      m->suspend = 0;
   }
}

int mthrd_is_running(int th_type) {
   if (th_type < MTHRD_TH_COUNT) {
      mthrd_t *m = &_g_mth.mthrd_ary[th_type];
      return !m->suspend;
   }
   return 0;
}

#ifdef PLAT_THREAD_TESTING
static void _th_add_1(void *param) {
   int *a = (int*)param;
   *a += 1;
   printf("1: a=%d\n", *a);
}

static void _th_sub_2(void *param) {
   int *a = (int*)param;
   *a -= 2;
   printf("2: a=%d\n", *a);
}

int main(int argc, char *argv[]) {
   int a = 0, b = 0;
   int time = 0;

   mthrd_init(0);

   mthrd_loop(MTHRD_MAIN, _th_add_1, &a, 10);
   mthrd_loop(MTHRD_MAIN, _th_sub_2, &a, 20);
   mthrd_loop(MTHRD_AUX, _th_add_1, &b, 10);
   mthrd_loop(MTHRD_AUX, _th_sub_2, &b, 20);

   time = 1000;
   while (--time >= 0) {
      /* dispatch_main(); */
      mtime_sleep(1);
   }

   mm_report(0);
   printf("----------\n");

   mthrd_fini();
   mm_report(0);
   return 0;
}
#endif
