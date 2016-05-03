/* 
 * Copyright (c) 2015 lalawue
 * 
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the MIT license. See LICENSE for details.
 */

#ifndef TUNNEL_REMOTE_H
#define TUNNEL_REMOTE_H

typedef enum {
   TUNNEL_REMOTE_MODE_INVALID = 0, /* invalid mode */
   TUNNEL_REMOTE_MODE_STANDALONE,  /* as back end proxy */
   TUNNEL_REMOTE_MODE_FORWARD,     /* as one node proxy */
} tunnel_remote_mode_t;

typedef struct {
   tunnel_remote_mode_t mode;
   int local_port;
   int forward_port;
   char local_ipaddr[16];
   char forward_ipaddr[16];   
   char username[32];
   char password[32];
} tunnel_remote_config_t;

int tunnel_remote_open(tunnel_remote_config_t*);
//void tunnel_remote_close(void);

#endif
