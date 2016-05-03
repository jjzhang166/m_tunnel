/* 
 * Copyright (c) 2015 lalawue
 * 
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the MIT license. See LICENSE for details.
 */

#ifndef UTILS_STR_H
#define UTILS_STR_H

#include <stdarg.h>

#define USTR_DELIM_MAX_LEN (64)
#define USTR_CMP_RESULT_INVALID (123456)

typedef struct s_str str_t;

/* functions create/destroy str head
 */
str_t* str_create_format(const char *fmt, ...);
str_t* str_clone_cstr(const char *cstr, int len);
str_t* str_dup(str_t*);
void str_destroy(str_t *m);


/* destroy original str will gc str created below
 */
str_t* str_link(str_t *m, str_t *n); /* add to child */
const char* str_dump(str_t *m);

/* find support pattern matching same as Lua-5.2.3 */
str_t* str_find(str_t *m, const char *pattern, int init);
int str_locate(str_t *m, const char *delim, int icase);
int str_cmp(str_t *m, const char *cstr, int icase);

str_t* str_sub(str_t *m, int from, int to);
str_t* str_trim(str_t *m, char trim);

char* str_cstr(str_t *m);
int str_len(str_t *m);

str_t* str_next(str_t *m);

#define str_foreach(_M, _LST)                   \
   for (str_t *_M=_LST; _M; _M=str_next(_M))

str_t* str_split(str_t *m, const char *delim, int icase);

int str_bsearch(str_t *m, str_t*);

void str_debug(str_t *m, int print, int child);

#endif
