/* 
 * Copyright (c) 2015 lalawue
 * 
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the MIT license. See LICENSE for details.
 */

#ifndef M_DICT_H
#define M_DICT_H

typedef struct s_dict dict_t;

dict_t* dict_create(int capacity);
void dict_destroy(dict_t*);

int dict_count(dict_t*);

void* dict_get(dict_t*, const char *key, int keylen);
int dict_set(dict_t*, const char *key, int keylen, void *data);

void* dict_remove(dict_t*, const char *key, int keylen);

typedef void(*dict_enumerate_callback)(
   void *opaque, const char *key, int keylen, void *value, int *stop);

void dict_foreach(dict_t*, dict_enumerate_callback cb, void *opaque);

#endif
