/* 
 * Copyright (c) 2015 lalawue
 * 
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the MIT license. See LICENSE for details.
 */

#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "m_mem.h"
#include "m_debug.h"
#include "utils_str.h"
#include "utils_misc.h"

#define _err(...) _mlog("utils", D_ERROR, __VA_ARGS__)

unsigned long misc_get_file_size(char *path) {
   unsigned long fsize = 0;
   FILE *fp = fopen(path, "rb");
   if ( fp ) {
      if (fseek(fp, 0, SEEK_END) == 0) {
         fsize = ftell(fp);
         fclose(fp);
      }
      else {
         goto err_get_fsize;
      }
   }
   else {
     err_get_fsize:
      _err("fail to get file size '%s'\n", path);
   }
   return fsize;
}

int misc_check_file_ro(const char *filename) {
   if ( filename ) {
      FILE *fp = fopen(filename, "rb");
      if ( fp ) {
         fclose(fp);
         return 1;
      }
   }
   return 0;
}

char* misc_read_file(const char* fileName, unsigned long *len) {
   char *fcontent = NULL;
   if (fileName && len) {
      long flength = 0;
      FILE *fp = fopen(fileName, "rb");
      if (fp == NULL) {
         _err("fail to open dns record !\n");
         goto fail;
      }

      assert(fseek(fp, 0, SEEK_END) == 0);
      flength = ftell(fp);
      if (flength < 0) {
         _err("fail to get dns record file size !\n");
         goto fail;
      }

      fcontent = (char*)mm_malloc(flength);
      if (fcontent == NULL) {
         _err("fail to malloc fcontent !\n");
      }

      if (fcontent) {
         rewind(fp);
         int ret = fread(fcontent, flength, 1, fp);
         if (ret < 0) {
            _err("fail to read dns record !\n");
            mm_free(fcontent);
            fcontent = NULL;
            goto fail;
         }
      
         *len = flength;
      }

     fail:
      if (fp) { fclose(fp); }
   }
   return fcontent;
}

int misc_write_file(const char* fileName, char *buf, unsigned long len) {
   int ret = 0;
   if (fileName && buf && len > 0) {
      FILE *fp = fopen(fileName, "wb");
      if ( fp ) {
         ret = fwrite(buf, 1, len, fp);
         fclose(fp);
         return ret;
      }
   }
   return ret;
}

char* misc_truncate_str(char *str, int len, char ch) {
   if ( str ) {
      while (str[len]!=ch && (--len > 0));
      if (str[len] == ch) str[len] = 0;
   }
   return str;
}

char* misc_strdup(char *from) {
   char *to = NULL;
   if ( from ) {
      unsigned len = (unsigned)strlen(from);
      to = (char*)mm_malloc(len + 1);
      strcpy(to, from);
   }
   return to;
}

char*
misc_locate_chr(char *str, int *len, char ch) {
   if ( str ) {
      int i = *len - 1;
      while (i>=0 && str[i]!=ch) { i--; }
      if (i < 0) { return str; }
      *len = *len - (++i);
      return &str[i];
   }
   return NULL;
}


void
misc_hex_addr(char *addr, int addr_len, unsigned char *e, int elen) {
   str_t *h = str_split(str_clone_cstr(addr, addr_len), ".", 0);
   int i = 0;
   str_foreach(s, h) {
      e[i++] = atoi(str_cstr(s));
   }
   str_destroy(h);
}

void
misc_print_hex(uint8_t *data, int len) {
   for (int i=0; i<len; i++) {
      printf("%02X", data[i]);
      if (i && ((i&1)==1)) {
         printf(" ");
      }
      if (i && ((i&0xf)==0xf)) {
         printf("\n");
      }
   }
   printf("\n");
}

const char*
misc_fix_str_1024(const char *s, int len) {
   static char str[1024];
   memset(str, 0, 1024);
   memcpy(str, s, _MIN_OF(len, 1024));
   return str;
}
