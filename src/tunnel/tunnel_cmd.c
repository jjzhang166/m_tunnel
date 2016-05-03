/* 
 * Copyright (c) 2015 lalawue
 * 
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the MIT license. See LICENSE for details.
 */

#include "m_debug.h"
#include "tunnel_cmd.h"
#include <string.h>
#include <assert.h>

#define _err(...) _mlog("cmd", D_ERROR, __VA_ARGS__)
#define _info(...) _mlog("cmd", D_INFO, __VA_ARGS__)
#define _verbose(...) _mlog("cmd", D_VERBOSE, __VA_ARGS__)

int
tunnel_cmd_check(buf_t *b, tunnel_cmd_t *cmd) {
   if (b && cmd && buf_buffered(b)>=TUNNEL_CMD_CONST_HEADER_LEN) {
      memset(cmd, 0, sizeof(*cmd));

      unsigned char *d = buf_addr(b,buf_ptr(b));
      cmd->data_len = tunnel_cmd_data_len(d, 0, 0);
      cmd->chann_id = tunnel_cmd_chann_id(d, 0, 0);
      cmd->magic = tunnel_cmd_chann_magic(d, 0, 0);
      cmd->cmd = tunnel_cmd_head_cmd(d, 0, 0);
      cmd->payload = &d[TUNNEL_CMD_CONST_HEADER_LEN];

      if (buf_buffered(b) >= cmd->data_len) {
         _verbose("chann %d:%d cmd %d, length %d\n", cmd->chann_id,
                  cmd->magic, cmd->cmd, cmd->data_len);
         return 1;
      }
      /* _err("not enought data %d:%d !\n", buf_buffered(b), cmd->data_len); */
   }
   return 0;
}

int
tunnel_cmd_data_len(unsigned char *data, int set, int data_len) {
   if (data) {
      if (set) {
         data[0] = (data_len >> 16 ) & 0xff;
         data[1] = (data_len >> 8 ) & 0xff;
         data[2] = data_len & 0xff;
         return data_len;
      }
      else {
         int len = (data[0] << 16) | (data[1] << 8) | data[2];
         return len;
      }
   }
   return -1;
}

int
tunnel_cmd_chann_id(unsigned char *data, int set, int chann_id) {
   if (data) {
      int base = 3;
      if (set) {
         data[base+0] = (chann_id >> 24) & 0xff;
         data[base+1] = (chann_id >> 16) & 0xff;
         data[base+2] = (chann_id >> 8) & 0xff;
         data[base+3] = (chann_id & 0xff);
         return chann_id;
      }
      else {
         return (data[base+0]<<24) | (data[base+1]<<16) | (data[base+2]<<8) | data[base+3];
      }
   }
   return -1;
}

int
tunnel_cmd_chann_magic(unsigned char *data, int set, int magic) {
   if (data) {
      int base = 3 + 4;
      if (set) {
         data[base+0] = (magic >> 24) & 0xff;
         data[base+1] = (magic >> 16) & 0xff;
         data[base+2] = (magic >> 8) & 0xff;
         data[base+3] = (magic & 0xff);
         return magic;
      }
      else {
         return (data[base+0]<<24) | (data[base+1]<<16) | (data[base+2]<<8) | data[base+3];
      }
   }
   return -1;
}

int
tunnel_cmd_head_cmd(unsigned char *data, int set, int cmd) {
   if (data) {
      int base = TUNNEL_CMD_CONST_HEADER_LEN - 1;
      if (set) {
         data[base] = (unsigned char)(cmd & 0xff);
         return cmd;
      }
      else {
         return data[base];
      }
   }
   return TUNNEL_CMD_NONE;
}
