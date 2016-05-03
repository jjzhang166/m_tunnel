/* 
 * Copyright (c) 2015 lalawue
 * 
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the MIT license. See LICENSE for details.
 */

#ifndef PLAT_THREAD_H
#define PLAT_THREAD_H

#define MTHRD_MODE_POWER_HIGH  0 /* sched no delay */
#define MTHRD_MODE_POWER_LOW   1 /* sched in milli seconds */

int mthrd_init(int mode);
void mthrd_fini(void);

#define MTHRD_MAIN 0   /* in main queue with POWER_LOW under OSX/iOS */
#define MTHRD_AUX  1
//#define MTHRD_3RD  2

/* return 1 to continue loop */
typedef int(*mthread_func)(void*);

int mthrd_after(int th_type, mthread_func func, void *ud, int ms);

void mthrd_suspend(int th_type);
void mthrd_resume(int th_type);

int mthrd_is_running(int th_type);

#endif
