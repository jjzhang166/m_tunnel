/* 
 * Copyright (c) 2015 lalawue
 * 
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the MIT license. See LICENSE for details.
 */

#ifndef TUNNEL_LOCAL_H
#define TUNNEL_LOCAL_H

#include <stdint.h>

typedef enum {
   TUNNEL_LOCAL_MODE_INVALID = 0, /* invalid mode */
   TUNNEL_LOCAL_MODE_STANDALONE,  /* as sock5 proxy */
} tunnel_local_mode_t;

typedef struct {
   tunnel_local_mode_t mode;
   int local_port;
   int remote_port;
   char local_ipaddr[16];
   char remote_ipaddr[16];
   char username[32];
   char password[32];
} tunnel_local_config_t;

int tunnel_local_open(tunnel_local_config_t*);
//void tunnel_local_close(void);

#endif
