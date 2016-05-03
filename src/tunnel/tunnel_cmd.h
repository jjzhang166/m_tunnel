/* 
 * Copyright (c) 2015 lalawue
 * 
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the MIT license. See LICENSE for details.
 */

#ifndef TUNNEL_CMD_H
#define TUNNEL_CMD_H

#include "m_buf.h"

/* [         HEADER            ] 
 * TOTAL_DATA_LEN | TUNNEL_CMD | PAYLOAD
 * 3 bytes        | 1 byte     | n bytes
 *
 * support data < 2^24 (16777216, 16Mb)
 */

#define TUNNEL_CMD_CONST_HEADER_LEN   4
#define TUNNEL_CMD_CONST_CHANN_ID_LEN 4

#define TUNNEL_CHANN_BUF_SIZE  (65536) /* 64 kb */
#define TUNNEL_CHANN_MAX_COUNT (1024)

typedef struct {
   unsigned short data_len;
   unsigned char cmd;
   unsigned char *data;         /* from buffer begin */
   unsigned char *payload;      /* from payload */
} tunnel_cmd_t;

enum {
   TUNNEL_CMD_NONE = 0,

   TUNNEL_CMD_ECHO,
   /* REQUEST : ECHO_VAL
                1 byte

      RESPONSE: 1
    */

   TUNNEL_CMD_AUTH,
   /* REQUEST : AUTH_TYPE | USER_NAME_LEN | USER_NAME_PAYLOAD | PASSWORD_LEN | PASSWORD_PAYLOAD
                1 byte    | 1 byte        | n bytes           | 1 byte       | n bytes


      RESPONSE: 1/0 (SUCCESS/FAIL)
                1 byte
    */

   TUNNEL_CMD_CONNECT,
   /* REQUEST : CHANN_ID | ADDR_TYPE | PORT_PAYLOAD | ADDR_PAYLOAD | NULL
                4 bytes  | 1 byte    | 2 bytes      |  n bytes     | '\0'

      RESPONSE: CHANN_ID | RESULT | PORT_PAYLOAD | ADDR_PAYLOAD
                4 bytes  | 1 byte | 2 bytes      | 4 bytes

      NOTE    : ADDR_TYPE should be 0/1 (dot numberic/domain)
                RESULT should be 0/1 (failure/success), failure will ignore ADDR and PORT
    */

   TUNNEL_CMD_CLOSE,
   /* REQUEST : CHANN_ID | 1
                4 bytes

      RESPONSE: CHANN_ID | 0
                4 bytes
      NOTE    : the RESPONSE only comes from remote, for local sync chann_id state
    */

   TUNNEL_CMD_DATA,
   /* REQUEST : CHANN_ID | DATA_PAYLOAD
                4 bytes  | n bytes
      
      NO RESPONSE
    */
};

enum {
   TUNNEL_ADDR_TYPE_IP = 0,
   TUNNEL_ADDR_TYPE_DOMAIN,
   TUNNEL_ADDR_TYPE_INVALID,    /* for connection failure */
};

int tunnel_cmd_check(buf_t *b, tunnel_cmd_t *cmd);

/* data should be buffer header */
int tunnel_cmd_data_len(unsigned char *data, int set, int data_len);
int tunnel_cmd_head_cmd(unsigned char *data, int set, int cmd);
int tunnel_cmd_chann_id(unsigned char *data, int set, int chann_id);

#endif
