#include <stdlib.h>
#include <sys/time.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>

#include "arp_cache.h"
#include "sr_protocol.h"

#define SHARED 0

static struct arp_cache_entry *new_arp_cache_entry(uint32_t ip_address, uint8_t *ethernet_address);

struct arp_cache *new_arp_cache() {
    struct arp_cache *cache = calloc(1, sizeof(struct arp_cache));
    cache->head = NULL;
    cache->tail = NULL;

    //initialize thread and start it
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setscope(&attr, PTHREAD_SCOPE_SYSTEM); //OS schedules the threads
    pthread_create(&cache->thread, &attr, clean_arp_cache, (void *) cache);

    //initialize semaphore
    int result = sem_init(&cache->semaphore, SHARED, 1);
    if(result != 0){
        fprintf(stderr, "ERROR: semaphore creation failed\n");
        exit(errno);
    }

    return cache;
}

void add_arp_cache_entry(struct arp_cache *cache, uint32_t ip_address, uint8_t *ethernet_address) {

    if(search_arp_cache(cache, ip_address)) {
        // Address already in cache
        return;
    }

    //P(semaphore)
    printf("adding an entry to arp cache\n");
    int result = sem_wait(&(cache->semaphore));
    if(result != 0) {
        fprintf(stderr, "ERROR: semaphore wait failed in add_cache_entry\n");
        exit(errno);
    }

    struct arp_cache_entry *entry = new_arp_cache_entry(ip_address, ethernet_address);

    if(! cache->head) {
        cache->head = entry;
        cache->tail = entry;

    } else {
        cache->tail->next = entry;
        cache->tail = entry;
    }

    //V(semaphore)
    result = sem_post(&(cache->semaphore));
    if(result != 0){
        fprintf(stderr, "ERROR: semaphore post failed in add_cache_entry\n");
        exit(errno);
    }
    printf("left add_arp_cache_entry\n");
}

uint8_t *search_arp_cache(struct arp_cache *cache, uint32_t ip_address) {
    //P(semaphore)
    int result = sem_wait(&(cache->semaphore));
    if(result != 0) {
        fprintf(stderr, "ERROR: semaphore wait failed in add_cache_entry\n");
        exit(errno);
    }

    struct arp_cache_entry *current = cache->head;

    while(current) {
        if(current->ip_address == ip_address) {
            // Refresh the entry in the cache
            gettimeofday(&current->last_refreshed, NULL);

            //V(semaphore)
            result = sem_post(&(cache->semaphore));
            if(result != 0){
                fprintf(stderr, "ERROR: semaphore post failed in add_cache_entry\n");
                exit(errno);
            }

            // Return the ethernet address
            return current->ethernet_address;
        }
        current = current->next;
    }

    //V(semaphore)
    result = sem_post(&(cache->semaphore));
    if(result != 0){
        fprintf(stderr, "ERROR: semaphore post failed in add_cache_entry\n");
        exit(errno);
    }

    return NULL;
}

void remove_old_entries(struct arp_cache *cache) {
    printf("trying to remove old entries\n");
    //P(semaphore)
    int result = sem_wait(&(cache->semaphore));
    if(result != 0) {
        fprintf(stderr, "ERROR: semaphore wait failed in add_cache_entry\n");
        exit(errno);
    }

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

        trail = current;
        current = current->next;
    }

    //V(semaphore)
    result = sem_post(&(cache->semaphore));
    if(result != 0){
        fprintf(stderr, "ERROR: semaphore post failed in add_cache_entry\n");
        exit(errno);
    }
    printf("removed an entry\n");
}

static struct arp_cache_entry *new_arp_cache_entry(uint32_t ip_address, uint8_t *ethernet_address) {
    struct arp_cache_entry *entry = malloc(sizeof(struct arp_cache_entry));
    entry->ip_address = ip_address;
    entry->ethernet_address = ethernet_address;
    gettimeofday(&entry->last_refreshed, NULL);
    entry->next = NULL;

    return entry;
}

void * clean_arp_cache(void * arg){

    //assign the cache to a normal thing
    struct arp_cache *cache = (struct arp_cache *) arg;

    //loop forever, check the old entries and sleep for the cache lifetime

    while(1){
        sleep(1);
        remove_old_entries(cache);
    }

}
