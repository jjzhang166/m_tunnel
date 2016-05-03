/* 
 * Copyright (c) 2015 lalawue
 * 
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the MIT license. See LICENSE for details.
 */

#ifndef TUNNEL_CMD_H
#define TUNNEL_CMD_H

#include "m_buf.h"

/* [                       HEADER                    ] 
 * TOTAL_DATA_LEN | CHANN_ID |  MAGIC   | TUNNEL_CMD | PAYLOAD
 * 3 bytes        | 4 bytes  |  4 bytes | 1 byte     | n bytes
 *
 * support data < 2^24 (16777216, 16M)
 */

#define TUNNEL_CMD_CONST_HEADER_LEN 12

#define TUNNEL_CHANN_BUF_SIZE  (64*1024)
#define TUNNEL_CHANN_MAX_COUNT (1024)

typedef struct {
   int data_len;
   int chann_id;
   int magic;
   int cmd;
   unsigned char *payload;      /* from payload */
} tunnel_cmd_t;

/* cmd and payload layout */
enum {
   TUNNEL_CMD_NONE = 0,

   TUNNEL_CMD_ECHO,
   /* REQUEST : ECHO_VAL
                1 byte

      RESPONSE: 1
    */

   TUNNEL_CMD_AUTH,
   /* REQUEST : AUTH_TYPE | USER_NAME | PASSWORD_PAYLOAD
                1 byte    | 16 byte   | 16 bytes


      RESPONSE: 1/0 (SUCCESS/FAIL)
                1 byte
    */

   TUNNEL_CMD_CONNECT,
   /* REQUEST : ADDR_TYPE | PORT_PAYLOAD | ADDR_PAYLOAD | NULL
                1 byte    | 2 bytes      |  n bytes     | '\0'

      RESPONSE: RESULT | PORT_PAYLOAD | ADDR_PAYLOAD
                1 byte | 2 bytes      | 4 bytes

      NOTE    : ADDR_TYPE should be 0/1 (dot numberic/domain)
                RESULT should be 0/1 (failure/success), failure will ignore ADDR and PORT
    */

   TUNNEL_CMD_CLOSE,
   /* REQUEST : CLOSE_VAL
                (1) 1 bytes

      RESPONSE: CLOSE_VAL
                (0) 1 bytes
      NOTE    : the RESPONSE only comes from remote, for local sync chann_id state
    */

   TUNNEL_CMD_DATA,
   /* REQUEST : DATA_PAYLOAD
                n bytes
      
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
int tunnel_cmd_chann_id(unsigned char *data, int set, int chann_id);
int tunnel_cmd_chann_magic(unsigned char *data, int set, int magic);
int tunnel_cmd_head_cmd(unsigned char *data, int set, int cmd);

#endif
