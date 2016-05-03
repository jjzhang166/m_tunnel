/* 
 * Copyright (c) 2015 lalawue
 * 
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the MIT license. See LICENSE for details.
 */

#ifndef PLAT_LOCK_H
#define PLAT_LOCK_H

/* simple atomic thread-safe lock, init to '0' */

#if defined(_WIN32) || defined(_WIN64)
#include <windows.h>

typedef long lock_t;
#define _try_lock(l) (InterlockedCompareExchange(&l, 1, 0) == 0)
#define _lock(l) do {} while (!_try_lock(l))
#define _unlock(l) InterlockedCompareExchange(&l, 0, 1)

#else

typedef int lock_t;
#define _try_lock(l) __sync_bool_compare_and_swap(&l, 0, 1)
#define _lock(l) do {} while (!_try_lock(l))
#define _unlock(l) __sync_bool_compare_and_swap(&l, 1, 0)

#endif

#endif
