#include <stdlib.h>
#include <sys/time.h>
#include <stdio.h>

#include "sr_protocol.h"
#include "arp_cache.h"

static struct arp_cache_entry *new_arp_cache_entry(uint32_t ip_address, uint8_t *ethernet_address);

struct arp_cache *new_arp_cache() {
    struct arp_cache *cache = calloc(1, sizeof(struct arp_cache));
    cache->head = NULL;
    cache->tail = NULL;

    return cache;
}

void add_arp_cache_entry(struct arp_cache *cache, uint32_t ip_address, uint8_t *ethernet_address) {
    if(search_arp_cache(cache, ip_address)) {
        // Address already in cache
        return;
    }

    struct arp_cache_entry *entry = new_arp_cache_entry(ip_address, ethernet_address);

    if(! cache->head) {
        cache->head = entry;
        cache->tail = entry;
    } else {
        cache->tail->next = entry;
        cache->tail = entry;
    }
}

uint8_t *search_arp_cache(struct arp_cache *cache, uint32_t ip_address) {
    struct arp_cache_entry *current = cache->head;

    while(current) {
        if(current->ip_address == ip_address) {
            // Refresh the entry in the cache
            gettimeofday(&current->last_refreshed, NULL);

            // Return the ethernet address
            return current->ethernet_address;
        }
        current = current->next;
    }

    return NULL;
}

void remove_old_entries(struct arp_cache *cache) {
    struct timeval now;
    gettimeofday(&now, NULL);

    struct arp_cache_entry *current = cache->head;
    struct arp_cache_entry *trail = NULL;

    while(current) {
        if((now.tv_sec - current->last_refreshed.tv_sec) > CACHE_LIFETIME) {
            if(trail) {
                // Removing a regular item from the cache
                trail->next = current->next;

                // Removing the last item in the cache
                if(current->next == NULL) {
                    cache->tail = trail;
                }
            } else {
                if(! cache->head->next) {
                    // Removing the only item in the cache
                    cache->head = NULL;
                    cache->tail = NULL;
                    break;
                } else {
                    // Removing the first item in the cache
                    cache->head = current->next;
                }
            }
        }

        current = current->next;
    }
}

static struct arp_cache_entry *new_arp_cache_entry(uint32_t ip_address, uint8_t *ethernet_address) {
    struct arp_cache_entry *entry = malloc(sizeof(struct arp_cache_entry));
    entry->ip_address = ip_address;
    entry->ethernet_address = ethernet_address;
    gettimeofday(&entry->last_refreshed, NULL);
    entry->next = NULL;

    return entry;
}
