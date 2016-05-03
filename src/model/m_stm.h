/* 
 * Copyright (c) 2015 lalawue
 * 
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the MIT license. See LICENSE for details.
 */

#ifndef M_STM_H
#define M_STM_H

typedef struct s_stm stm_t;
typedef void(*stm_finalizer)(void *ptr, void *ud);

void stm_init(void);
void stm_fini(void);

stm_t* stm_create(const char *name, stm_finalizer f, void *ud);
stm_t* stm_retrive(const char *name);
void stm_clear(stm_t*);

int stm_count(stm_t*);

int stm_pushf(stm_t*, void *data);
int stm_pushl(stm_t*, void *data);

void* stm_popf(stm_t*);
void* stm_popl(stm_t*);

int stm_total(void);

#endif
