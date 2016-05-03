/* 
 * Copyright (c) 2015 lalawue
 * 
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the MIT license. See LICENSE for details.
 */

#if defined(_WIN32) || defined(_WIN64)

typedef long long int64_t;
typedef unsigned long long uint64_t;

#define snprintf _snprintf
#define atoll vs_atoll
#define strncasecmp _strnicmp
#define strcasecmp _stricmp
#define strcasestr vs_strcasestr

#ifdef __cplusplus
extern "C" {
#endif
   long long vs_atoll(const char *instr);
   char* vs_strcasestr(const char *s1, const char *s2);
#ifdef __cplusplus
}
#endif

#endif
