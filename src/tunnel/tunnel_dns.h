/* 
 * Copyright (c) 2015 lalawue
 * 
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the MIT license. See LICENSE for details.
 */

#ifndef _TUNNEL_DNS_H
#define _TUNNEL_DNS_H

#define TUNNEL_DNS_ADDR_LEN (16)
#define TUNNEL_DNS_DOMAIN_LEN (378)

int dns_domain_is_block(const char *domain, int domain_len);

int dns_domain_query_ip(
   const char *domain, int domain_len, char *addr, int addr_len);

int dns_domain_query_ip_local(
   const char *domain, int domain_len, char *addr, int addr_len);

int dns_domain_set_ip_local(
   const char *domain, int domain_len, char *addr, int addr_len);

void dns_save(void);
void dns_restore(const char *entry_path, const char *block_path);

#endif
