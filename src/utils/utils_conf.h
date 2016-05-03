/* 
 * Copyright (c) 2015 lalawue
 * 
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the MIT license. See LICENSE for details.
 */

#ifndef UTILS_CONF_H
#define UTILS_CONF_H

#include "m_list.h"
#include "utils_str.h"

typedef struct {
   str_t *key;
   str_t *value;
} conf_entry_t;

typedef struct {
   lst_t *entry_lst;
   void  *opaque_0;
   void  *opaque_1;
} conf_t;

conf_t* utils_conf_open(const char *conf_file);
void utils_conf_close(conf_t*);

str_t* utils_conf_value(conf_t*, const char *key);

#endif
