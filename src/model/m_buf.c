/* 
 * Copyright (c) 2015 lalawue
 * 
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the MIT license. See LICENSE for details.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "m_buf.h"
#include "m_mem.h"

buf_t* buf_create_ex(int len, char *fname, int line) {
   if (len > 0) {
      buf_t *b = (buf_t*)mm_malloc_ex(sizeof(*b)+len, fname, line);
      b->buf_len = len;
      b->buf = ((unsigned char*)b) + sizeof(*b);
      return b;
   }
   return NULL;
}

void buf_destroy(buf_t *b) {
   if (b) mm_free(b);
}

int buf_fmt(buf_t *b, const char *fmt, ...) {
   int ret = 0;
   if ( b ) {
      va_list ap;
      va_start(ap, fmt);
      ret = vsnprintf((char*)&b->buf[b->ptw], b->buf_len - b->ptw, fmt, ap);
      va_end(ap);
      b->ptw += ret;
   }
   return ret;
}

unsigned char* buf_addr(buf_t *b, int offset) {
   return (((offset>=0) && (offset<b->buf_len)) ? &(b->buf[offset]) : NULL);
}

int buf_forward_ptr(buf_t *b, int offset) {
   if (b && (b->ptr+offset)<=b->ptw && (b->ptr+offset)>=0) {
      b->ptr += offset;
      return offset;
   }
   return (int)0xfffffff;
}

int buf_forward_ptw(buf_t *b, int offset) {
   if (b && (b->ptw+offset)<=b->buf_len && (b->ptw+offset)>=0) {
      b->ptw += offset;
      return offset;
   }
   return (int)0xfffffff;
}

void buf_debug(buf_t *b) {
   if ( b ) {
      printf("[buf] b:%p, len:%d, ptw:%d\n", b, b->buf_len, b->ptw);
   }
}
