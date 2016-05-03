/* 
 * Copyright (c) 2015 lalawue
 * 
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the MIT license. See LICENSE for details.
 */

#ifndef M_BUF_H
#define M_BUF_H

#include <stdarg.h>

typedef struct s_buf {
   void *ud;
   int buf_len;
   int ptr, ptw;
   unsigned char *buf;
} buf_t;

buf_t* buf_create_ex(int, char*, int);
#define buf_create(len) buf_create_ex((len), __FILE__, __LINE__)

void buf_destroy(buf_t *b);

#define buf_set_ud(b, val) ((b)->ud = (val))
#define buf_get_ud(b) ((b)->ud)

#define buf_available(b) ((b)->buf_len - (b)->ptw)
#define buf_buffered(b) ((b)->ptw - (b)->ptr)
#define buf_len(b) ((b)->buf_len)

int buf_fmt(buf_t *b, const char *fmt, ...);
#define buf_reset(b) ((b)->ptw = (b)->ptr = 0)

unsigned char* buf_addr(buf_t *b, int offset);

#define buf_ptr(b) ((b)->ptr)
#define buf_ptw(b) ((b)->ptw)

int buf_forward_ptr(buf_t *b, int offset);
int buf_forward_ptw(buf_t *b, int offset);

void buf_debug(buf_t *b);

#endif
