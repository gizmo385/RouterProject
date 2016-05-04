#ifndef _IP_CACHE_H
#define _IP_CACHE_H

#include <sys/time.h>

#include "sr_protocol.h"

#define CACHE_LIFETIME 15

struct ip_cache_entry {
    uint8_t *packet;
    struct timeval last_refreshed;

    struct ip_cache_entry *next;
};

struct ip_cache {
    struct ip_cache_entry *head;
    struct ip_cache_entry *tail;
};

extern struct ip_cache *new_ip_cache();

extern void add_ip_cache_entry(struct ip_cache *cache, uint8_t *packet);

extern void remove_old_ip_entries(struct ip_cache *cache, uint8_t *addr);

#endif
