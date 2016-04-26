#ifndef _ARP_CACHE_H
#define _ARP_CACHE_H

#include <sys/time.h>

#include "sr_protocol.h"

#define CACHE_LIFETIME 15

struct arp_cache_entry {
    uint32_t ip_address;
    uint8_t *ethernet_address;
    struct timeval last_refreshed;

    struct arp_cache_entry *next;
};

struct arp_cache {
    struct arp_cache_entry *head;
    struct arp_cache_entry *tail;
};

extern struct arp_cache *new_arp_cache();

extern void add_arp_cache_entry(struct arp_cache *cache, uint32_t ip_address,
        uint8_t *ethernet_address);

extern uint8_t *search_arp_cache(struct arp_cache *cache, uint32_t ip_address);

extern void remove_old_entries(struct arp_cache *cache);

#endif
