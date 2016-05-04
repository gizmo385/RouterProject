#ifndef _IP_CACHE_H
#define _IP_CACHE_H

#include "sr_protocol.h"

#define CACHE_LIFETIME 15

struct ip_cache_entry {
    uint8_t *packet;
    struct in_addr nexthop;
    uint32_t len;
    struct ip_cache_entry *next;
};

struct ip_cache {
    struct ip_cache_entry *head;
    struct ip_cache_entry *tail;
};

extern struct ip_cache *new_ip_cache();

extern void add_ip_cache_entry(struct ip_cache *cache, uint8_t *packet, struct in_addr nexthop,
        uint32_t len);

extern struct ip_cache_entry *next_packet_with_dest(struct ip_cache *cache, struct in_addr dest);

#endif
