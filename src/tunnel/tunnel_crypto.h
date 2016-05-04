/* 
 * Copyright (c) 2016 lalawue
 * 
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the MIT license. See LICENSE for details.
 */

#ifndef TUNNEL_CRYPTO_H
#define TUNNEL_CRYPTO_H

uint64_t mc_hash_key(const char * str, int sz);

int mc_encrypt(const char *in, int sz, char *out, uint64_t key, time_t ti);
int mc_decrypt(const char *in, int sz, char *out, uint64_t key, time_t ti);

int mc_enc(unsigned char *data, int data_len);
int mc_dec(unsigned char *data, int data_len);

#endif
