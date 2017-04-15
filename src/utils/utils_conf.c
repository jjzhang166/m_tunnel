/* 
 * Copyright (c) 2015 lalawue
 * 
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the MIT license. See LICENSE for details.
 */

#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>

#include "m_mem.h"
#include "utils_conf.h"

#define _err(...) do { printf("[conf] "); printf(__VA_ARGS__); } while (0)

conf_t*
utils_conf_open(const char *conf_file) {
   //mm_report(2);
   conf_t *cf = NULL;
   FILE *fp = fopen(conf_file, "rb");
   if (fp) {
      if (fseek(fp, 0, SEEK_END) == 0) {

         long flength = ftell(fp);
         char *fcontent = (char*)mm_malloc(flength);
         
         rewind(fp);
         if (fread(fcontent, flength, 1, fp) > 0) {

            lst_t *lst = lst_create();
            str_t *h = str_split(str_clone_cstr(fcontent, flength), "\n", 0);

            if (h) {
               str_foreach(it, h) {
                  conf_entry_t *ce = (conf_entry_t*)mm_malloc(sizeof(*ce));
                  str_t *se = str_split(it, "\t", 0);
                  ce->key = se;
                  ce->value = str_next(se);
                  lst_pushl(lst, ce);
               }

               cf = (conf_t*)mm_malloc(sizeof(*cf));
               cf->entry_lst = lst;
               cf->opaque_0 = fcontent;
               cf->opaque_1 = h;
            }
            else {
               _err("empty conf file !\n");
               lst_destroy(lst);
            }
         }
         else {
            _err("fail to read [%s] !\n", conf_file);
            mm_free(fcontent);
         }
      }
      else {
         _err("fail to seek conf file !\n");
      }
      fclose(fp);
   }
   else {
      _err("fail to open conf file !\n");
   }
   return cf;
}

void
utils_conf_close(conf_t *cf) {
   if (cf) {
      mm_free(cf->opaque_0);
      str_destroy((str_t*)cf->opaque_1);
      while (lst_count(cf->entry_lst) > 0) {
         mm_free(lst_popf(cf->entry_lst));
      }
      lst_destroy(cf->entry_lst);
      mm_free(cf);
      //mm_report(2);
   }
}

str_t*
utils_conf_value(conf_t *cf, const char *key) {
   str_t *val = NULL;
   if (cf && key) {
      lst_foreach(it, cf->entry_lst) {
         conf_entry_t *ce = (conf_entry_t*)lst_iter_data(it);

         if (str_cmp(ce->key, key, 0) == 0) {
            val = ce->value;
            break;
         }
      }
   }
   return val;
}
