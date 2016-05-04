#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "sr_protocol.h"
#include "ip_cache.h"

static struct ip_cache_entry *new_ip_cache_entry(uint8_t *whole_packet){
	struct ip_cache_entry *entry = calloc(1, sizeof(struct ip_cache_entry));
	entry->packet = whole_packet;
	entry->next = NULL;

	return entry; 
}

struct ip_cache *new_ip_cache(){
	struct ip_cache *ip_cache = calloc(1, sizeof(struct ip_cache));
	ip_cache->head = NULL;
	ip_cache->tail = NULL;

	return ip_cache;
}

void add_ip_cache_entry(struct ip_cache *cache, uint8_t *packet){
	struct ip_cache_entry *new_entry = new_ip_cache_entry(packet);

	if(!cache->head){
		cache->head = new_entry;
		cache->tail = new_entry;
	} else {
		cache->tail->next = new_entry;
		cache->tail = new_entry;
	}
}

void remove_old_ip_entries(struct ip_cache *cache, uint8_t *addr) {

	struct ip_cache_entry *current = cache->head;
	struct ip *ip_header = malloc(sizeof(struct ip));

	memcpy(ip_header, current + sizeof(struct sr_ethernet_hdr), sizeof(struct ip));

//	while(current){
		
		//if the entry has this new address, remove it from cache and send it
		
//	}
}

