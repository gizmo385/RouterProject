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

static void route_ip_packet(struct sr_instance *sr, uint8_t *packet, char *interface);

static char *search_routing_table(struct sr_instance *sr, uint32_t ip_to_lookup);

static void send_arp_request(struct sr_instance *sr, char *interface, uint32_t ip_to_find);

static uint8_t *pack_ethernet_packet(uint8_t *destination_host, uint8_t *source_host,
        uint16_t ether_type, char *packet, size_t len);

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
                        printf("IT's an ARP reply!\n");
                        add_arp_cache_entry(cache, arp_header->ar_sip, arp_header->ar_sha);
                        struct in_addr addr = {arp_header->ar_sip};
                        printf("Mapping %s to ", inet_ntoa(addr));
                        fwrite(arp_header->ar_sha, sizeof(char), ETHER_ADDR_LEN, stdout);
                        break;
                }
                break;
            }
        case ETHERTYPE_IP:
            {
                // TODO
                printf("\tIt's an IP packet!\n");
                route_ip_packet(sr, packet, interface);
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
static void send_arp_request(struct sr_instance *sr, char *interface, uint32_t ip_to_find) {
    // Get the interface address
    struct sr_if *iface = sr_get_interface(sr, interface);

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
    arp_header->ar_hln = htons(ETHER_ADDR_LEN);
    arp_header->ar_pln = htons(INET_ADDRSTRLEN);
    arp_header->ar_op = htons(ARP_REQUEST);

    // Important fields in request
    memcpy(&arp_header->ar_sha, iface->addr, ETHER_ADDR_LEN);
    bzero(&arp_header->ar_tha, ETHER_ADDR_LEN);
    memcpy(&arp_header->ar_sip, &iface->ip, sizeof(uint32_t));
    memcpy(&arp_header->ar_tip, &ip_to_find, sizeof(uint32_t));

    // Stuff the packet into an ethernet header
    uint8_t broadcast[ETHER_ADDR_LEN];
    memset(&broadcast, 0xFF, ETHER_ADDR_LEN);
    uint8_t *message_buffer = pack_ethernet_packet(broadcast, iface->addr, ETHERTYPE_ARP,
            (char *) arp_header, sizeof(struct sr_arphdr));

    sr_send_packet(sr, message_buffer, sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arphdr),
            interface);
}

static void route_ip_packet(struct sr_instance *sr, uint8_t *packet, char *interface){
    // Parse Ethernet header and IP header out of packet
    struct sr_ethernet_hdr ethernet_header;
    memcpy(&ethernet_header, packet, sizeof(struct sr_ethernet_hdr));

    struct ip ip_header;
    memcpy(&ip_header, packet + sizeof(struct sr_ethernet_hdr), sizeof(struct ip));

    // Decrement the TTL and check if it's 0
    ip_header.ip_ttl -= 1;
    if(ip_header.ip_ttl <= 0) {
        return;
    } else {
        // TODO Update the checksum
    }

    // Get the IP packet's destination
    struct in_addr destination_addr = ip_header.ip_dst;
    uint32_t destination_ip = destination_addr.s_addr;

    // Check if we're the destination
    struct sr_if *iface = sr_get_interface(sr, interface);
    if(destination_ip == iface->ip) {
        printf("Dropping packet bound for router on %s\n", interface);
        return;
    }

	// Check the routing table for the correct packet
	char *destination = search_routing_table(sr, destination_ip);

    if(!destination) {
        // Send an ARP request to the destination IP on a specific interface
        send_arp_request(sr, interface, destination_ip);
    } else {
        // Forward packet to the correct subsystem
    }
}

/*---------------------------------------------------------------------
 * Method: search_routing_table
 * Scope: local
 *
 * Attemepts to find the ethernet address for a particular IP in the routing table
 *
 *---------------------------------------------------------------------*/
static char *search_routing_table(struct sr_instance *sr, uint32_t ip_to_lookup) {
    return NULL; // TODO while(true) { fix; mem; }
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
            ETHERTYPE_ARP, (char *) &arp_reply, sizeof(struct sr_arphdr));
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
        uint16_t ether_type, char *packet, size_t len) {
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
