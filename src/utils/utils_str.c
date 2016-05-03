/* 
 * Copyright (c) 2015 lalawue
 * 
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the MIT license. See LICENSE for details.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stddef.h>

#include <ctype.h>
#include <string.h>

#if defined(_WIN32) || defined(_WIN64)
#include "plat_type.h"
#else
#include <strings.h>
#endif

#include "m_mem.h"
#include "m_debug.h"

#include "utils_str.h"
#include <assert.h>

#define _err(...) _mlog("ustr", D_ERROR, __VA_ARGS__)
#define _info(...) _mlog("ustr", D_INFO, __VA_ARGS__)

#define _FMT_SIZE 4096

struct s_str {
   char *cstr;
   int len;
   str_t *next;                 /* for split, next */
   str_t *child;                /* child for gc, destroy */
   str_t *parent;               /* parent of str */
};

static inline str_t*
_child(str_t *parent, str_t *child) {
   child->child = parent->child;
   child->parent = parent;
   parent->child = child;
   return child;
}

/* pattern matching from Lua-5.2.3 */

/*
  Copyright © 1994–2013 Lua.org, PUC-Rio.  Permission is hereby granted,
  free of charge, to any person obtaining a copy of this software and
  associated documentation files (the "Software"), to deal in the Software
  without restriction, including without limitation the rights to use,
  copy, modify, merge, publish, distribute, sublicense, and/or sell copies
  of the Software, and to permit persons to whom the Software is furnished
  to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included
  in all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
  OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

/*
** {======================================================
** PATTERN MATCHING
** =======================================================
*/

#define LUA_MAXCAPTURES		32

/* macro to `unsign' a character */
#define uchar(c)	((unsigned char)(c))

#define CAP_UNFINISHED	(-1)
#define CAP_POSITION	(-2)


typedef struct MatchState {
   int matchdepth; /* control for recursive depth (to avoid C stack overflow) */
   const char *src_init;  /* init of source string */
   const char *src_end;  /* end ('\0') of source string */
   const char *p_end;  /* end ('\0') of pattern */
   int level;  /* total number of captures (finished or unfinished) */
   str_t *m;
   struct {
      const char *init;
      ptrdiff_t len;
   } capture[LUA_MAXCAPTURES];
} MatchState;


/* recursive function */
static const char *match (MatchState *ms, const char *s, const char *p);


/* maximum recursion depth for 'match' */
#if !defined(MAXCCALLS)
#define MAXCCALLS	200
#endif


#define L_ESC		'%'
#define SPECIALS	"^$*+?.([%-"


static int check_capture (MatchState *ms, int l) {
   l -= '1';
   if (l < 0 || l >= ms->level || ms->capture[l].len == CAP_UNFINISHED) {
      //return luaL_error(ms->L, "invalid capture index %%%d", l + 1);
      _err("invalid capture index %d\n", l + 1);
      return -1;
   }
   return l;
}


static int capture_to_close (MatchState *ms) {
   int level = ms->level;
   for (level--; level>=0; level--)
      if (ms->capture[level].len == CAP_UNFINISHED) return level;
   //return luaL_error(ms->L, "invalid pattern capture");
   _err("invalid pattern capture\n");
   return -1;
}


static const char *classend (MatchState *ms, const char *p) {
   switch (*p++) {
      case L_ESC: {
         if (p == ms->p_end) {
            //luaL_error(ms->L, "malformed pattern (ends with " LUA_QL("%%") ")");
            return NULL;
         }
         return p+1;
      }
      case '[': {
         if (*p == '^') p++;
         do {  /* look for a `]' */
            if (p == ms->p_end) {
               //luaL_error(ms->L, "malformed pattern (missing " LUA_QL("]") ")");
               return NULL;
            }
            if (*(p++) == L_ESC && p < ms->p_end)
               p++;  /* skip escapes (e.g. `%]') */
         } while (*p != ']');
         return p+1;
      }
      default: {
         return p;
      }
   }
}


static int match_class (int c, int cl) {
   int res;
   switch (tolower(cl)) {
      case 'a' : res = isalpha(c); break;
      case 'c' : res = iscntrl(c); break;
      case 'd' : res = isdigit(c); break;
      case 'g' : res = isgraph(c); break;
      case 'l' : res = islower(c); break;
      case 'p' : res = ispunct(c); break;
      case 's' : res = isspace(c); break;
      case 'u' : res = isupper(c); break;
      case 'w' : res = isalnum(c); break;
      case 'x' : res = isxdigit(c); break;
      case 'z' : res = (c == 0); break;  /* deprecated option */
      default: return (cl == c);
   }
   return (islower(cl) ? res : !res);
}


static int matchbracketclass (int c, const char *p, const char *ec) {
   int sig = 1;
   if (*(p+1) == '^') {
      sig = 0;
      p++;  /* skip the `^' */
   }
   while (++p < ec) {
      if (*p == L_ESC) {
         p++;
         if (match_class(c, uchar(*p)))
            return sig;
      }
      else if ((*(p+1) == '-') && (p+2 < ec)) {
         p+=2;
         if (uchar(*(p-2)) <= c && c <= uchar(*p))
            return sig;
      }
      else if (uchar(*p) == c) return sig;
   }
   return !sig;
}


static int singlematch (MatchState *ms, const char *s, const char *p,
                        const char *ep) {
   if (s >= ms->src_end)
      return 0;
   else {
      int c = uchar(*s);
      switch (*p) {
         case '.': return 1;  /* matches any char */
         case L_ESC: return match_class(c, uchar(*(p+1)));
         case '[': return matchbracketclass(c, p, ep-1);
         default:  return (uchar(*p) == c);
      }
   }
}


static const char *matchbalance (MatchState *ms, const char *s,
                                 const char *p) {
   if (p >= ms->p_end - 1) {
      //luaL_error(ms->L, "malformed pattern " "(missing arguments to " LUA_QL("%%b") ")");
      _err("malformed pattern (missing arguments)\n");
      return NULL;
   }
   if (*s != *p) return NULL;
   else {
      int b = *p;
      int e = *(p+1);
      int cont = 1;
      while (++s < ms->src_end) {
         if (*s == e) {
            if (--cont == 0) return s+1;
         }
         else if (*s == b) cont++;
      }
   }
   return NULL;  /* string ends out of balance */
}


static const char *max_expand (MatchState *ms, const char *s,
                               const char *p, const char *ep) {
   ptrdiff_t i = 0;  /* counts maximum expand for item */
   while (singlematch(ms, s + i, p, ep))
      i++;
   /* keeps trying to match with the maximum repetitions */
   while (i>=0) {
      const char *res = match(ms, (s+i), ep+1);
      if (res) return res;
      i--;  /* else didn't match; reduce 1 repetition to try again */
   }
   return NULL;
}


static const char *min_expand (MatchState *ms, const char *s,
                               const char *p, const char *ep) {
   for (;;) {
      const char *res = match(ms, s, ep+1);
      if (res != NULL)
         return res;
      else if (singlematch(ms, s, p, ep))
         s++;  /* try with one more repetition */
      else return NULL;
   }
}


static const char *start_capture (MatchState *ms, const char *s,
                                  const char *p, int what) {
   const char *res;
   int level = ms->level;
   if (level >= LUA_MAXCAPTURES) {
      //luaL_error(ms->L, "too many captures");
      _err("too many captures\n");
      return NULL;
   }
   ms->capture[level].init = s;
   ms->capture[level].len = what;
   ms->level = level+1;
   if ((res=match(ms, s, p)) == NULL)  /* match failed? */
      ms->level--;  /* undo capture */
   return res;
}


static const char *end_capture (MatchState *ms, const char *s,
                                const char *p) {
   int l = capture_to_close(ms);
   const char *res;
   if (l < 0) return NULL;
   ms->capture[l].len = s - ms->capture[l].init;  /* close capture */
   if ((res = match(ms, s, p)) == NULL)  /* match failed? */
      ms->capture[l].len = CAP_UNFINISHED;  /* undo capture */
   return res;
}


static const char *match_capture (MatchState *ms, const char *s, int l) {
   size_t len;
   l = check_capture(ms, l);
   if (l < 0) return NULL;
   len = ms->capture[l].len;
   if ((size_t)(ms->src_end-s) >= len &&
       memcmp(ms->capture[l].init, s, len) == 0)
      return s+len;
   else return NULL;
}


static const char *match (MatchState *ms, const char *s, const char *p) {
   if (ms->matchdepth-- == 0) {
      //luaL_error(ms->L, "pattern too complex");
      _err("pattern too complex\n");
      return NULL;
   }
  init: /* using goto's to optimize tail recursion */
   if (p != ms->p_end) {  /* end of pattern? */
      switch (*p) {
         case '(': {  /* start capture */
            if (*(p + 1) == ')')  /* position capture? */
               s = start_capture(ms, s, p + 2, CAP_POSITION);
            else
               s = start_capture(ms, s, p + 1, CAP_UNFINISHED);
            break;
         }
         case ')': {  /* end capture */
            s = end_capture(ms, s, p + 1);
            break;
         }
         case '$': {
            if ((p + 1) != ms->p_end)  /* is the `$' the last char in pattern? */
               goto dflt;  /* no; go to default */
            s = (s == ms->src_end) ? s : NULL;  /* check end of string */
            break;
         }
         case L_ESC: {  /* escaped sequences not in the format class[*+?-]? */
            switch (*(p + 1)) {
               case 'b': {  /* balanced string? */
                  s = matchbalance(ms, s, p + 2);
                  if (s != NULL) {
                     p += 4; goto init;  /* return match(ms, s, p + 4); */
                  }  /* else fail (s == NULL) */
                  break;
               }
               case 'f': {  /* frontier? */
                  const char *ep; char previous;
                  p += 2;
                  if (*p != '[') {
                     //luaL_error(ms->L, "missing " LUA_QL("[") " after " LUA_QL("%%f") " in pattern");
                     _err("missing [ after in pattern\n");
                     s = NULL;       // by sc
                     break;
                  }
                  ep = classend(ms, p);  /* points to what is next */
                  if (ep == NULL) { s = NULL; break; } // by sc
                  previous = (s == ms->src_init) ? '\0' : *(s - 1);
                  if (!matchbracketclass(uchar(previous), p, ep - 1) &&
                      matchbracketclass(uchar(*s), p, ep - 1)) {
                     p = ep; goto init;  /* return match(ms, s, ep); */
                  }
                  s = NULL;  /* match failed */
                  break;
               }
               case '0': case '1': case '2': case '3':
               case '4': case '5': case '6': case '7':
               case '8': case '9': {  /* capture results (%0-%9)? */
                  s = match_capture(ms, s, uchar(*(p + 1)));
                  if (s != NULL) {
                     p += 2; goto init;  /* return match(ms, s, p + 2) */
                  }
                  break;
               }
               default: goto dflt;
            }
            break;
         }
         default: dflt: {  /* pattern class plus optional suffix */
            const char *ep = classend(ms, p);  /* points to optional suffix */
            /* does not match at least once? */
            if (!singlematch(ms, s, p, ep)) {
               if (*ep == '*' || *ep == '?' || *ep == '-') {  /* accept empty? */
                  p = ep + 1; goto init;  /* return match(ms, s, ep + 1); */
               }
               else  /* '+' or no suffix */
                  s = NULL;  /* fail */
            }
            else {  /* matched once */
               switch (*ep) {  /* handle optional suffix */
                  case '?': {  /* optional */
                     const char *res;
                     if ((res = match(ms, s + 1, ep + 1)) != NULL)
                        s = res;
                     else {
                        p = ep + 1; goto init;  /* else return match(ms, s, ep + 1); */
                     }
                     break;
                  }
                  case '+':  /* 1 or more repetitions */
                     s++;  /* 1 match already done */
                     /* go through */
                  case '*':  /* 0 or more repetitions */
                     s = max_expand(ms, s, p, ep);
                     break;
                  case '-':  /* 0 or more repetitions (minimum) */
                     s = min_expand(ms, s, p, ep);
                     break;
                  default:  /* no suffix */
                     s++; p = ep; goto init;  /* return match(ms, s + 1, ep); */
               }
            }
            break;
         }
      }
   }
   ms->matchdepth++;
   return s;
}

static int _posrelat(int pos, int len) {
   if (pos >= 0) return pos;
   else if ((0 - pos) > len) return 0;
   else return len - pos + 1;
}

/* check whether pattern has no special characters */
static int _nospecials (const char *p, size_t l) {
   size_t upto = 0;
   do {
      if (strpbrk(p + upto, SPECIALS))
         return 0;  /* pattern has a special character */
      upto += strlen(p + upto) + 1;  /* may have more after \0 */
   } while (upto <= l);
   return 1;  /* no special chars found */
}

static const char *_memfind (const char *s1, size_t l1,
                             const char *s2, size_t l2) {
   if (l2 == 0) return s1;  /* empty strings are everywhere */
   else if (l2 > l1) return NULL;  /* avoids a negative `l1' */
   else {
      const char *init;  /* to search for a `*s2' inside `s1' */
      l2--;  /* 1st char will be checked by `memchr' */
      l1 = l1-l2;  /* `s2' cannot be found after that */
      while (l1 > 0 && (init = (const char *)memchr(s1, *s2, l1)) != NULL) {
         init++;   /* 1st char is already checked */
         if (memcmp(init, s2+1, l2) == 0)
            return init-1;
         else {  /* correct `l1' and `s1' to try again */
            l1 -= init-s1;
            s1 = init;
         }
      }
      return NULL;  /* not found */
   }
}

static str_t* _push_onecapture (MatchState *ms, int i, const char *s,
                                const char *e) {
   if (i >= ms->level) {
      if (i == 0) { /* ms->level == 0, too */
         //lua_pushlstring(ms->L, s, e - s);  /* add whole match */
         return str_clone_cstr(s, e - s);
      }
      else {
         //luaL_error(ms->L, "invalid capture index");
         _err("invalid capture index\n");
         return NULL;
      }
   }
   else {
      ptrdiff_t l = ms->capture[i].len;
      if (l == CAP_UNFINISHED) {
         //luaL_error(ms->L, "unfinished capture");
         _err("unfinished capture\n");
         return NULL;
      }
#if 0 /* no more capture position */
      if (l == CAP_POSITION) {
         lua_pushinteger(ms->L, ms->capture[i].init - ms->src_init + 1);
      }
#endif
      //lua_pushlstring(ms->L, ms->capture[i].init, l);
      return str_clone_cstr(ms->capture[i].init, l);
   }
}

static str_t* _push_captures (MatchState *ms, const char *s, const char *e) {
   int i;
   int nlevels = (ms->level == 0 && s) ? 1 : ms->level;
   str_t *h=NULL, *p=NULL;
   for (i = 0; i < nlevels; i++) {
      str_t *n = _push_onecapture(ms, i, s, e);
      if (n == NULL) return NULL;
      if (h == NULL) { h=n; _child(ms->m, h); p=h;}
      else { p->next=n; _child(p, n); p=n; }
   }
   return h;  /* number of strings pushed */
}

/* End of PATTERN MATCHING */

static str_t*
_str_format(const char *fmt, va_list ap) {
   char *p = (char*)mm_malloc(_FMT_SIZE);
   int n = vsnprintf(p, _FMT_SIZE, fmt, ap);
   if (n >= _FMT_SIZE) {
      int sz = n * 2;
      for (;;) {
         p = (char*)mm_realloc(p, sz);
         n = vsnprintf(p, sz, fmt, ap);
         if (n < sz) {
            break;
         }
         sz *= 2;
      }
   }

   str_t *m = (str_t*)mm_malloc(sizeof(*m) + n);
   m->cstr = (((char*)m) + sizeof(*m));
   m->len = n;
   memcpy(m->cstr, p, n);
   mm_free(p);
   return  m;
}

str_t*
str_create_format(const char *fmt, ...) {
   if (fmt) {
      str_t *m = NULL;
      va_list ap;
      va_start(ap, fmt);
      m = _str_format(fmt, ap);
      va_end(ap);
      return m;
   }
   return NULL;
}

str_t*
str_dup(str_t *s) {
   if ( s ) {
      str_t *c = (str_t*)mm_malloc(sizeof(*c) + s->len);
      c->len = s->len;
      c->cstr = (((char*)c) + sizeof(*c));
      memcpy(c->cstr, s->cstr, s->len);
      return c;
   }
   return NULL;
}

str_t*
str_clone_cstr(const char *cstr, int len) {
   if ( cstr ) {
      str_t *m = (str_t*)mm_malloc(sizeof(*m));
      m->cstr = (char*)cstr;
      m->len = len;
      return m;
   }
   return NULL;
}

/* description: destroy any sub/split str will cause all str be freed
 */
void
str_destroy(str_t *m) {
   if ( m ) {
      str_t *n = m;
      while (n->parent) {
         n = n->parent;
      }
      while ( n ) {
         str_t *child = n->child;
         mm_free(n);
         n = child;
      }
   }
}

str_t*
str_link(str_t *m, str_t *n) {
   if ( m ) {
      return _child(m, n);
   }
   return NULL;
}

const char*
str_dump(str_t *m) {
   if ( m ) {
      char *p = (char*)mm_malloc(m->len + 1);
      snprintf(p, m->len + 1, "%s", m->cstr);
      p[m->len] = '\0';
      return p;
   }
   return NULL;
}

str_t*
str_find(str_t *m, const char *pattern, int pos) {
   if (m && pattern) {
      int ls, lp;
      const char *s = m->cstr;
      const char *p = pattern;
      ls = m->len;
      lp = strlen(pattern);
      int init = _posrelat(pos, lp);
      if (init < 1) init = 1;
      else if (init > ls + 1) { /* start after string's end? */
         return NULL;          /* cannot find anything */
      }
      /* no special characters? */
      if ( _nospecials(p, lp) ) {
         /* do a plain search */
         const char *s2 = _memfind(s + init - 1, ls - init + 1, p, lp);
         if (s2) {
            return _child(m, str_clone_cstr(s2, lp));
         }
      }
      else {
         MatchState ms;
         const char *s1 = s + init - 1;
         int anchor = (*p == '^');
         ms.m = m;
         if (anchor) {
            p++; lp--;      /* skip anchor character */
         }
         ms.matchdepth = MAXCCALLS;
         ms.src_init = s;
         ms.src_end = s + ls;
         ms.p_end = p + lp;
         do {
            const char *res;
            ms.level = 0;
            //lua_assert(ms.matchdepth == MAXCCALLS);
            if (ms.matchdepth != MAXCCALLS) {
               _err("match depth !\n");
               break;
            }
            if ((res=match(&ms, s1, p)) != NULL) {
               return _push_captures(&ms, s1, res);
            }
         } while (s1++ < ms.src_end && !anchor);
      }
   }
   return NULL;
}

int
str_locate(str_t *m, const char *pattn, int icase) {
   if (m && pattn) {
      int dlen = strnlen(pattn, USTR_DELIM_MAX_LEN);
      if (m->len >= dlen) {
         char *p = icase ? strcasestr(m->cstr, pattn) : strstr(m->cstr, pattn);
         if ( p ) {
            return (p - m->cstr);
         }
      }
   }
   return -1;
}

int
str_cmp(str_t *m, const char *cstr, int icase) {
   if (m && cstr) {
      int ret = icase ? strncasecmp(m->cstr, cstr, m->len)
         : strncmp(m->cstr, cstr, m->len);
      return ret;
   }
   return USTR_CMP_RESULT_INVALID;
}

str_t*
str_sub(str_t *m, int from, int to) {
   if (m && (from>=0) && (to>0) && (to > from)) {
      if ((from>m->len) || (to>m->len)) {
         return NULL;
      }
      return _child(m, str_clone_cstr(&m->cstr[from], to - from));
   }
   return NULL;
}

str_t*
str_trim(str_t *m, char trim) {
   if ( m ) {
      char *p = m->cstr;
      int len = m->len;
      while ((len>0) && (*p == trim)) {
         p++;
         len--;
      }
      while ((len>0) && (p[len-1] == trim)) {
         len--;
      }
      if (len > 0) {
         return _child(m, str_clone_cstr(p, len));
      }
   }
   return NULL;
}

char*
str_cstr(str_t *m) {
   return m ? m->cstr : NULL;
}

int
str_len(str_t *m) {
   return m ? m->len : -1;
}

str_t*
str_next(str_t *m) {
   return m ? m->next : NULL;
}

str_t*
str_split(str_t *m, const char *delim, int icase) {
   if (m && delim) {
      int dlen = strnlen(delim, USTR_DELIM_MAX_LEN);
      if ((dlen>0) && (m->len>dlen)) {
         //_info("search v\n");
         str_t *head=NULL, *h=NULL;
         char *p = m->cstr;
         do {
            char *n = icase ? strcasestr(p, delim) : strstr(p, delim);
            //_info("n = %s, %ld\n", n, n - m->cstr);
            if (p == m->cstr) {
               if ((n==NULL) || ((n - m->cstr) > m->len)) {
                  break;
               }
            }
            else {
               if ((n==NULL) || ((n - m->cstr) > m->len)) {
                  n = &m->cstr[m->len];
               }
            }
            {
               str_t *nm = _child(m, str_clone_cstr(p, n-p));
               if (head == NULL) {
                  head = nm;
               }
               else {
                  h->next = nm;
               }
               h = nm;
            }
            p = n + dlen;
         } while ((p - m->cstr) < m->len);
         return head;
      }
   }
   return NULL;
}

static inline int
_binary_search(char *a, int alen, char *p, int plen) {
   if (a == p) { return 0; }
   if (plen > alen) { return -1; }
   int i, j;
   for (i=0; i<alen-plen; i++) {
      for (j=0; j<plen; j++) {
         if (a[i+j] != p[j]) { break; }
      }
      if (j == plen) {
         return i;
      }
   }
   return -1;
}

int str_bsearch(str_t *a, str_t *b) {
   if (a && b) {
      return _binary_search(a->cstr, a->len, b->cstr, b->len);
   }
   return -1;
}

/* description: it will modify the buffer content
 */
void
str_debug(str_t *m, int print_len, int child) {
   if ( m ) {
      str_t *n = m;
      while (n) {
         printf("%d:", n->len);
         int len = print_len<0 ? n->len : print_len;
         if (len && (len<=n->len)) {
            char tmp = n->cstr[len];
            n->cstr[len] = '\0';
            printf("%s", n->cstr);
            n->cstr[len] = tmp;
         }
         printf("\n");
         n = child ? n->next : NULL;
      }
   }
}


#ifdef TEST_UTILS_STR
static char *_cstr = "HTTP/1.1 200 OK\r\n\
Server: nginx\r\n\
Date: Fri, 15 Oct 2120 11:11:42 GMT\r\n\
Content-Type: text/html; charset=utf-8\r\n\
Content-Length: 16417\r\n\
Connection: keep-alive\r\n\
Keep-Alive: timeout=10\r\n\
Expires: Sun, 1 Jan 2006 01:00:00 GMT\r\n\
Cache-Control: must-revalidate, no-cache, private\r\n\
Set-Cookie: bid=\"LxgigAb3Clk\"; path=/; domain=.douban.com; expires=Sat, 02-Jan-2016 16:10:20 GMT\r\n\
Set-Cookie: ll=\"130294\"; path=/; domain=.douban.com; expires=Sat, 02-Jan-2016 16:24:51 GMT\r\n\
content-encoding: gzip\r\n\r\n";

static void
_test_cookies(str_t *head) {
   head = str_split(head, ":", 0);
   str_t *lst = str_split(str_next(head), ";", 0);
   char key[64], value[64];    
   printf("----- test sub cookies\n");
   str_foreach(k, lst) {
      memset(key, 0, 64);
      memset(value, 0, 64);

      str_t *n = str_split(k, "=", 0);

      str_t *p = str_trim(n, ' ');
      strncpy(key, str_cstr(p), str_len(p));

      p = str_trim(str_next(n), ' ');
      strncpy(value, str_cstr(p), str_len(p));

      printf("kv [%s] [%s] %d\n", key, value, str_len(n));
   }
   printf("----- end sub cookies\n");
}

int main(int argc, char *argv[])
{
   mm_report(2);

   char *cstr = mm_malloc(strlen(_cstr));
   strcpy(cstr, _cstr);

   str_t *head = str_clone_cstr(cstr, strlen(cstr));
   assert(head);

   printf("----- test find pattern\n");
   str_t *f = str_find(head, "Server", 0);
   str_debug(f, -1, 0);
   f = str_find(head, "Content%-Length: +(%d+)\r", 0);
   str_debug(f, -1, 0);

   printf("----- test split \n");
   str_t *lst = str_split(head, "\r\n", 0);
   assert(lst);
   str_foreach(k, lst) {
      char *cstr = str_cstr(k);
      int clen = str_len(k);
      if (clen > 0) {
         printf("%c|", cstr[0]);
         str_debug(k, -1, 0);

         if (str_locate(k, "set-cookie", 1) == 0) {
            _test_cookies(k);
         }
      }
   }

   str_t *new_head = str_create_format("%s", str_cstr(head));
   assert(new_head);

   /* destroy the head will free all mem created by it, except new */
   str_destroy(head);

   printf("----- test split none exist \n");
   str_t *nlst = str_split(new_head, "....", 0);
   str_debug(nlst, -1, 1);

   printf("----- ??? \n");

   nlst = str_split(new_head, "gzip", 0);
   str_debug(nlst, -1, 1);

   int sub_idx = str_locate(nlst, "keep-alive", 1);
   printf("sub idx %d\n", sub_idx);
   str_t *v = str_sub(nlst, sub_idx + 4, sub_idx + 10);
   assert(v);
   str_debug(v, -1, 0);

   //str_destroy(new_head);
   str_destroy(nlst);
   mm_free(cstr);
   mm_report(2);
   return 0;
}

/* gcc -g -Wall -I../plat -I../model ../model/m_mem.c ../model/m_debug.c utils_str.c -DTEST_UTILS_STR */
#endif
