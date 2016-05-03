/* 
 * Copyright (c) 2015 lalawue
 * 
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the MIT license. See LICENSE for details.
 */

#include "m_debug.h"
#include "tunnel_cmd.h"

#define _err(...) _mlog("cmd", D_ERROR, __VA_ARGS__)
#define _info(...) _mlog("cmd", D_INFO, __VA_ARGS__)
#define _verbose(...) _mlog("cmd", D_VERBOSE, __VA_ARGS__)

int
tunnel_cmd_check(buf_t *b, tunnel_cmd_t *cmd) {
   if (b && cmd && buf_buffered(b)>=TUNNEL_CMD_CONST_HEADER_LEN) {
      unsigned char *d = buf_addr(b,buf_ptr(b));
      cmd->data_len = tunnel_cmd_data_len(d, 0, 0);
      cmd->cmd = tunnel_cmd_head_cmd(d, 0, 0);
      cmd->data = d;
      cmd->payload = &d[TUNNEL_CMD_CONST_HEADER_LEN];
      if (buf_buffered(b) >= cmd->data_len) {
         return 1;
      }
      //_err("not enought data %d:%d !\n", buf_buffered(b), cmd->data_len);
   }
   return 0;
}

int
tunnel_cmd_data_len(unsigned char *data, int set, int data_len) {
   if (data) {
      if (set) {
         data[0] = (data_len >> 16) & 0xff;
         data[1] = (data_len >> 8 ) & 0xff;
         data[2] = data_len & 0xff;
         return data_len;
      }
      else {
         return (data[0] << 16) | (data[1] << 8) | data[2];
      }
   }
   return -1;
}

int
tunnel_cmd_head_cmd(unsigned char *data, int set, int cmd) {
   if (data) {
      int base = TUNNEL_CMD_CONST_HEADER_LEN - 1;
      if (set) {
         data[base] = cmd;
         return cmd;
      }
      else {
         return data[base];
      }
   }
   return TUNNEL_CMD_NONE;
}

int
tunnel_cmd_chann_id(unsigned char *data, int set, int chann_id) {
   if (data) {
      int base = TUNNEL_CMD_CONST_HEADER_LEN;
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


