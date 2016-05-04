#include <stdlib.h>
#include <stdio.h>

#include "sr_protocol.h"
#include "ip_cache.h"

static struct ip_cache_entry *new_ip_cache_entry(uint8_t *whole_packet, struct in_addr nexthop,
        uint32_t len){
	struct ip_cache_entry *entry = calloc(1, sizeof(struct ip_cache_entry));
	entry->packet = whole_packet;
    entry->nexthop = nexthop;
    entry->len = len;
	entry->next = NULL;

	return entry;
}

struct ip_cache *new_ip_cache(){
	struct ip_cache *ip_cache = calloc(1, sizeof(struct ip_cache));
	ip_cache->head = NULL;
	ip_cache->tail = NULL;

	return ip_cache;
}

void add_ip_cache_entry(struct ip_cache *cache, uint8_t *packet, struct in_addr nexthop,
        uint32_t len) {
	struct ip_cache_entry *new_entry = new_ip_cache_entry(packet, nexthop, len);

    printf("*** -> Adding new packet to the cache\n");

	if(!cache->head){
		cache->head = new_entry;
		cache->tail = new_entry;
	} else {
		cache->tail->next = new_entry;
		cache->tail = new_entry;
	}
}

struct ip_cache_entry *next_packet_with_dest(struct ip_cache *cache, struct in_addr dest) {
    struct ip_cache_entry *trail = NULL;
    struct ip_cache_entry *current = cache->head;

    struct ip_cache_entry *result = NULL;

    while(current) {
        if(current->nexthop.s_addr == dest.s_addr) {
            // Assign the packet being returned
            result = current;
            printf("\tRemoving packet bound for %s from the cache\n", inet_ntoa(dest));

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


            break;
        } else {
            trail = current;
            current = current->next;
        }
    }

    return result;
}

