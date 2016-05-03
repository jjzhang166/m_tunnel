/* 
 * Copyright (c) 2015 lalawue
 * 
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the MIT license. See LICENSE for details.
 */

#include <ctype.h>
#include <string.h>
#include "plat_type.h"

#if defined(_WIN32) || defined(_WIN64)

long long vs_atoll(const char *instr) {
   long long retval = 0;
   for (; (*instr>='0')&&(*instr<='9'); instr++) {  
      retval = 10*retval + (*instr - '0');  
   }  
   return retval;  
}

char *  
vs_strcasestr(const char *s, const char *find) {  
   /** Less code size, but quadratic performance in the worst case.  */  
   char c, sc;  
   int len;  
  
   if ((c = *find++) != 0) {  
      c = tolower((unsigned char)c);  
      len = strlen(find);  
      do {  
         do {  
            if ((sc = *s++) == 0)  
               return (NULL);  
         } while ((char)tolower((unsigned char)sc) != c);  
      } while (strncasecmp(s, find, len) != 0);  
      s--;  
   }  
   return ((char *)s);  
}

#endif
