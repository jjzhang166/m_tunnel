/* 
 * Copyright (c) 2015 lalawue
 * 
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the MIT license. See LICENSE for details.
 */

#ifndef M_MEM_H
#define M_MEM_H

void* mm_malloc_ex(unsigned long, char*, int);
#define mm_malloc(sz) mm_malloc_ex((sz),__FILE__,__LINE__)

void* mm_realloc_ex(void*,unsigned long, char*, int);
#define mm_realloc(ptr,sz) mm_realloc_ex((ptr),(sz),__FILE__,__LINE__)

unsigned long mm_free_ex(void*, char*, int);
#define mm_free(ptr) mm_free_ex(ptr,__FILE__,__LINE__)

int mm_has(void*);
void mm_report(int brief_level);

#endif



