/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing. 11
 * 90904102
 **********************************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <strings.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"

#include "arp_cache.h"

/* Function prototypes */
static void handle_arp_request(struct sr_instance *sr, struct sr_ethernet_hdr *ethernet_header,
        struct sr_arphdr *arp_header, char *interface);

static void route_ip_packet(struct sr_instance *sr, uint8_t *packet, size_t len, char *interface);

static struct sr_rt *search_routing_table(struct sr_instance *sr, uint32_t ip_to_lookup);

static void send_arp_request(struct sr_instance *sr, struct sr_if *iface,
        struct in_addr destination);

static uint8_t *pack_ethernet_packet(uint8_t *destination_host, uint8_t *source_host,
        uint16_t ether_type, uint8_t *packet, size_t len);

struct arp_cache *cache;

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Add initialization code here! */
    cache = new_arp_cache();

} /* -- sr_init -- */


/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

static void print_ethernet_addr(uint8_t *addr, FILE *file) {
    for(int i = 0; i < ETHER_ADDR_LEN; i++) {
        if(i == (ETHER_ADDR_LEN - 1)) {
            fprintf(file, "%X", addr[i]);
        } else {
            fprintf(file, "%X:", addr[i]);
        }
    }
}

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);

    printf("*** -> Received packet of length %d on interface \"%s\"\n", len, interface);

    // Deconstruct the packet's ethernet header
    struct sr_ethernet_hdr *header = malloc(sizeof(struct sr_ethernet_hdr));
    memcpy(header, packet, sizeof(struct sr_ethernet_hdr));
    header->ether_type = htons(header->ether_type);

    // Determine proper routing behavior based on ether_type
    switch(header->ether_type) {
        case ETHERTYPE_ARP:
            {
                // Unpack the ARP header
                struct sr_arphdr *arp_header = malloc(sizeof(struct sr_arphdr));
                memcpy(arp_header, packet + 14, sizeof(struct sr_arphdr));
                arp_header->ar_op = ntohs(arp_header->ar_op);

                // Check the ARP opcode
                switch(arp_header->ar_op) {
                    case ARP_REQUEST:
                        handle_arp_request(sr, header, arp_header, interface);
                        break;
                    case ARP_REPLY:
                        printf("\tIt's an ARP reply!\n");
                        // Add to the ARP cache
                        add_arp_cache_entry(cache, arp_header->ar_sip, arp_header->ar_sha);

                        struct in_addr addr = {arp_header->ar_sip};
                        printf("\tMapping %s to ", inet_ntoa(addr));
                        print_ethernet_addr(arp_header->ar_sha, stdout);
                        printf("\n");
                        break;
                }
                break;
            }
        case ETHERTYPE_IP:
            {
                // TODO
                printf("\tIt's an IP packet!\n");
                route_ip_packet(sr, packet, len, interface);
                break;
            }
        default:
            {
                printf("\tIt's an unknown packet type (ether_type = 0x%X)\n", header->ether_type);
                break;
            }
    }

} /* end sr_ForwardPacket */

/*---------------------------------------------------------------------
 * Method: send_arp_request(struct sr_instance *, char *, char *)
 * Scope:  Global
 *
 * Broadcasts an ARP request looking for ip_to_find on the interface supplied
 *
 *---------------------------------------------------------------------*/
static void send_arp_request(struct sr_instance *sr, struct sr_if *iface,
        struct in_addr destination) {
    /*
     * Important info from header
     *  ----------------------------------------------------------
     * |   Sender MAC   |   Sender IP  | Target MAC  | Target IP  |
     * | interface MAC  | interface IP |  UNKNOWN    | ip_to_find |
     *  ----------------------------------------------------------
     *
     * */
    struct sr_arphdr *arp_header = malloc(sizeof(struct sr_arphdr));

    // Protocol information
    arp_header->ar_hrd = htons(ARPHDR_ETHER);
    arp_header->ar_pro = htons(ETHERTYPE_IP);
    arp_header->ar_hln = ETHER_ADDR_LEN;
    arp_header->ar_pln = INET_ADDR_LEN;
    arp_header->ar_op = htons(ARP_REQUEST);

    // Important fields in request
    memcpy(&arp_header->ar_sha, iface->addr, ETHER_ADDR_LEN);
    bzero(&arp_header->ar_tha, ETHER_ADDR_LEN);
    memcpy(&arp_header->ar_sip, &iface->ip, sizeof(uint32_t));
    memcpy(&arp_header->ar_tip, &destination.s_addr, sizeof(uint32_t));

    struct in_addr ip_addr = { iface->ip };
    printf("*** -> Sent ARP request from %s (%s) looking for ", inet_ntoa(ip_addr), iface->name);
    printf("%s\n", inet_ntoa(destination));

    // Stuff the packet into an ethernet header
    uint8_t broadcast[ETHER_ADDR_LEN];
    memset(&broadcast, 0xFF, ETHER_ADDR_LEN);
    uint8_t *message_buffer = pack_ethernet_packet(broadcast, iface->addr, ETHERTYPE_ARP,
            (uint8_t *) arp_header, sizeof(struct sr_arphdr));

    sr_send_packet(sr, message_buffer, sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arphdr),
            iface->name);
}

#define CHECKSUM_ALIGNMENT 16
static uint16_t header_checksum(uint16_t *header, int count) {
    uint32_t sum = 0;

    while(count--) {
        sum += *header++;

        if(sum & 0xFFFF0000) {
            // Carry Occurred
            sum &= 0xFFFF;
            sum++;
        }
    }

    return ~(sum & 0xFFFF);
}

static void route_ip_packet(struct sr_instance *sr, uint8_t *packet, size_t len, char *interface) {
    // Copy the IP header
    struct ip *ip_header = malloc(sizeof(struct ip));
    memcpy(ip_header, packet + sizeof(struct sr_ethernet_hdr), sizeof(struct ip));

    // The IP header is a dirty liar
    int actual_header_length = ip_header->ip_hl * 4;

    // Decrement the TTL and check if it's 0
    ip_header->ip_ttl -= 1;
    if(ip_header->ip_ttl <= 0) {
        return;
    }

    // Zero out the old checksum
    ip_header->ip_sum = 0;

    // Create a buffer to calculate the checksum
    uint16_t *header_buffer;

    // Create a chunk of memory aligned to 16 bits
    posix_memalign((void **) &header_buffer, CHECKSUM_ALIGNMENT, actual_header_length);
    bzero(header_buffer, actual_header_length);

    // Copy required IP header fields
    memcpy(header_buffer, ip_header, sizeof(struct ip));

    // Copy the original IP header flags
    memcpy(header_buffer, packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip),
            actual_header_length - sizeof(struct ip));

    // Calculate the new checksum
    ip_header->ip_sum = header_checksum(header_buffer, actual_header_length / 2);

    free(header_buffer);

    // Get the IP packet's destination
    struct in_addr destination_addr = ip_header->ip_dst;
    uint32_t destination_ip = destination_addr.s_addr;

    // Check if we're the destination
    struct sr_if *iface = sr_get_interface(sr, interface);
    if(destination_ip == iface->ip) {
        printf("Dropping packet bound for router on %s\n", interface);
        return;
    }

    // Check the routing table for the correct gateway to forward the packet through
    struct sr_rt *table_entry = search_routing_table(sr, destination_ip);

    if(table_entry) {
        // Get the interface for the gateway
        struct sr_if *gw_iface = sr_get_interface(sr, table_entry->interface);

        // Look up the MAC address of the gateway in the ARP cache
        uint8_t *gw_addr = search_arp_cache(cache, table_entry->gw.s_addr);

        if(gw_addr) {
            printf("\tForwarding packet bound for %s through next hop @ ",
                    inet_ntoa(destination_addr));
            printf("%s (", inet_ntoa(table_entry->gw));
            print_ethernet_addr(gw_addr, stdout);
            printf(")\n");

            // Send the packet to this address
            uint8_t *updated_packet = malloc(ip_header->ip_len);
            memcpy(updated_packet, ip_header, actual_header_length);
            memcpy(updated_packet + actual_header_length,
                    packet + sizeof(struct sr_ethernet_hdr ) + actual_header_length,
                    len - sizeof(struct sr_ethernet_hdr ) - actual_header_length);

            uint8_t *buffer = pack_ethernet_packet(gw_addr, gw_iface->addr, ETHERTYPE_IP,
                    updated_packet, ip_header->ip_len);

            sr_send_packet(sr, buffer, len, gw_iface->name);
        } else {
            // Otherwise we cache the IP packet and make an ARP request
            // TODO: Cache the IP packet
            send_arp_request(sr, gw_iface, table_entry->gw);
        }

    } else {
        // TODO: What do we do here?
    }
}

/*---------------------------------------------------------------------
 * Method: search_routing_table
 * Scope: local
 *
 * Attempts to find the next hop for a particular IP address
 *
 *---------------------------------------------------------------------*/
static struct sr_rt *search_routing_table(struct sr_instance *sr, uint32_t ip_to_lookup) {

    struct sr_rt *rt_walker = sr->routing_table;

    while(rt_walker) {
        // Get the netmask from the routing table entry
        uint32_t mask = rt_walker->mask.s_addr;
        uint32_t dest = rt_walker->dest.s_addr;

        if((ip_to_lookup & mask) == (dest & mask)) {
            // This means we've found the correct gateway to forward the packet to
            return rt_walker;
        } else {
            rt_walker = rt_walker->next;
        }
    }

    return NULL;
}

/*---------------------------------------------------------------------
 * Method: handle_arp_request
 * Scope: local
 *
 * Handles an ARP request sent to an interface.
 *
 *---------------------------------------------------------------------*/
static void handle_arp_request(struct sr_instance *sr, struct sr_ethernet_hdr *ethernet_header,
        struct sr_arphdr *arp_header, char *interface) {
    printf("\tIt's an ARP request!\n");

    // Get the interface address
    struct sr_if* iface = sr_get_interface(sr, interface);
    if ( iface == 0 ) {
        fprintf( stderr, "** Error, interface %s, does not exist\n", interface);
    }

    // Create ARP reply :)
    struct sr_arphdr arp_reply;
    memcpy(&arp_reply, arp_header, sizeof(struct sr_arphdr));
    arp_reply.ar_op = htons(ARP_REPLY);
    memcpy(&arp_reply.ar_sha, iface->addr, ETHER_ADDR_LEN);
    memcpy(&arp_reply.ar_tha, arp_header->ar_sha, ETHER_ADDR_LEN);
    memcpy(&arp_reply.ar_sip, &(arp_header->ar_tip), sizeof(uint32_t));
    memcpy(&arp_reply.ar_tip, &(arp_header->ar_sip), sizeof(uint32_t));

    // Send the reply
    uint8_t *buffer = pack_ethernet_packet(ethernet_header->ether_shost, iface->addr,
            ETHERTYPE_ARP, (uint8_t *) &arp_reply, sizeof(struct sr_arphdr));
    sr_send_packet(sr, buffer, sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arphdr),
            interface);
}

/*---------------------------------------------------------------------
 * Method: pack_ethernet_packet
 * Scope: Local
 *
 * Wraps a packet in an ethernet header, adds both the header and packet to a buffer, and returns
 * the buffer.
 *
 *---------------------------------------------------------------------*/
static uint8_t *pack_ethernet_packet(uint8_t *destination_host, uint8_t *source_host,
        uint16_t ether_type, uint8_t *packet, size_t len) {
    // Create the ethernet header
    struct sr_ethernet_hdr header;
    memcpy(&header.ether_dhost, destination_host, ETHER_ADDR_LEN);
    memcpy(&header.ether_shost, source_host, ETHER_ADDR_LEN);
    header.ether_type = htons(ether_type);

    // Pack the header and packet into a buffer
    size_t header_size = sizeof(struct sr_ethernet_hdr);
    uint8_t *buffer = malloc(header_size + len);
    memcpy(buffer, &header, header_size);
    memcpy(buffer + header_size, packet, len);

    return buffer;
}


/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/
