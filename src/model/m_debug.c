/* 
 * Copyright (c) 2015 lalawue
 * 
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the MIT license. See LICENSE for details.
 */
#if defined(_WIN32) || defined(_WIN64) 
#include <windows.h>
#else
#define _XOPEN_SOURCE 500
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#endif

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include "m_debug.h"
#include "plat_type.h"

typedef struct {
   int init;
   int level;
   int option;
   FILE *fp;
} debug_t;

static debug_t _g_dbg;

static inline debug_t*  _dbg(void) {
   return &_g_dbg;
}

void debug_open(char *fname) {
   debug_t *d = _dbg();
   if (fname && !d->init) {
      if (strcmp(fname, "stdout") == 0) {
         d->fp = stdout;
      }
      else if (strcmp(fname, "stderr") == 0) {
         d->fp = stderr;
      }
      else {
         d->fp = fopen(fname, "a");
         assert( d->fp );
      }
      d->option = D_OPT_DEFAULT;
      d->level = D_VERBOSE;
      fprintf(d->fp, "### debug open (%s)\n", fname);
      d->init = 1;
      return;
   }
   assert(0);
}

void debug_close(void) {
   debug_t *d = _dbg();
   if ( d->init ) {
      fprintf(d->fp, "### debug close\n");
      if ( d->fp ) {
         if (d->fp!=stdout && d->fp!=stderr) {
            fclose(d->fp);
         }
      }
      d->init = 0;
   }
}

void debug_set_option(int opt) {
   debug_t *d = _dbg();
   if ( d->init ) {
      d->option = opt;
      fprintf(d->fp, "### debug option (0x%x)\n", opt);
      return;
   }
   assert(0);
}

void debug_set_level(int level) {
   debug_t *d = _dbg();
   if ( d->init ) {
      d->level = level;
      fprintf(d->fp, "### debug level (%d)\n", level);
      return;
   }
   assert(0);
}

void debug_raw(const char *fmt, ...) {
   debug_t *d = _dbg();
   if ( d->init ) {
      va_list ap;
      va_start(ap, fmt);
      vfprintf(d->fp, fmt, ap);
      va_end(ap);

      if (d->option & D_OPT_FLUSH) {
         fflush(d->fp);
      }
   }
}

/* micro second */
int64_t debug_time(void) {
#if defined(_WIN32) || defined(_WIN64)
   FILETIME ft;
   int64_t t;
   GetSystemTimeAsFileTime(&ft);
   t = (int64_t)ft.dwHighDateTime << 32 | ft.dwLowDateTime;
   return t / 10 - 11644473600000000; /* Jan 1, 1601 */
#else
   struct timeval tv;
   gettimeofday(&tv, NULL);
   return (int64_t)tv.tv_sec * 1000000 + (int64_t)tv.tv_usec;
#endif
}

void
debug_log(const char *mod, int level, const char *fname,
          int line, const char *fmt, ...)
{
   debug_t *d = _dbg();

   if ( d->init ) {

      if (level > d->level) {
         return;
      }

      if (d->option & D_OPT_LEVEL) {
         static char *clev[D_VERBOSE + 1] = {
            "Err", "Warn", "Info", "Verbose"
         };
         level = level & D_VERBOSE;
         fprintf(d->fp, "%s) ", clev[level]);
      }

      if (d->option & D_OPT_TIME) {
#if defined(_WIN32) || defined(_WIN64)
         int64_t tm = debug_time();
         fprintf(d->fp, "%u> ", tm);
#else
         struct tm stm; time_t tloc; struct timeval tv;
         tloc = time(NULL);
         localtime_r(&tloc, &stm);
         gettimeofday(&tv, NULL);
         fprintf(d->fp, "%d/%d %02d:%02d:%02d.%03d> ",
                 stm.tm_mon+1, stm.tm_mday, stm.tm_hour,
                 stm.tm_min, stm.tm_sec, (int)tv.tv_usec>>10);
#endif
      }

      if ((d->option & D_OPT_FILE) && fname) {
         char *p = strrchr((char*)fname, '/');
         if ( p ) {
            fprintf(d->fp, "(%s:%d) ", p+1, line);
         } else {
            fprintf(d->fp, "(%s:%d) ", fname, line);
         }
      }

      fprintf(d->fp, "[%s] ", mod);

      va_list ap;
      va_start(ap, fmt);
      vfprintf(d->fp, fmt, ap);
      va_end(ap);

      if (d->option & D_OPT_FLUSH) {
         fflush(d->fp);
      }
   }
}
