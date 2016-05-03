/* 
 * Copyright (c) 2015 lalawue
 * 
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the MIT license. See LICENSE for details.
 */

#ifndef UTILS_MISC_H
#define UTILS_MISC_H

#include <stdint.h>

#define _MAX_OF(A, B) (((A)>(B)) ? (A) : (B))
#define _MIN_OF(A, B) (((A)<(B)) ? (A) : (B))

int   misc_check_file_ro(const char *filename);
char* misc_read_file(const char* fileName, unsigned long *len);
int   misc_write_file(const char* fileName, char *buf, unsigned long len);

char* misc_truncate_str(char *str, int len, char ch);
char* misc_strdup(char *from);
char* misc_locate_chr(char *str, int *len, char ch);

unsigned long misc_get_file_size(char *path);
void misc_hex_addr(char *addr, int addr_len, unsigned char *e, int elen);
void misc_print_hex(uint8_t *data, int len);

const char* misc_fix_str_1024(const char *s, int len);

#endif
