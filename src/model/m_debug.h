/* 
 * Copyright (c) 2015 lalawue
 * 
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the MIT license. See LICENSE for details.
 */

#include <stdarg.h>

/* option for log */
#define D_OPT_LEVEL   1         /* log level info */
#define D_OPT_TIME    2         /* log time */
#define D_OPT_FILE    4         /* log fname & fline */

#define D_OPT_THREAD  8         /* not implement */
#define D_OPT_FLUSH   16        /* flush every log */

#define D_OPT_DEFAULT (D_OPT_TIME | D_OPT_FILE)
#define D_OPT_ALL     0xff

/* level */
#define D_ERROR   0
#define D_WARN    1
#define D_INFO    2
#define D_VERBOSE 3             // default

extern void debug_open(char*);
extern void debug_close(void);

extern void debug_set_option(int);
extern void debug_set_level(int);

extern void debug_raw(const char *fmt, ...);
extern void debug_log(const char *mod, int level, const char *fname,
                      int line, const char *fmt, ...);

#define _mlog(MOD, LEV, ...)                            \
   debug_log(MOD, LEV, __FILE__, __LINE__, __VA_ARGS__)
