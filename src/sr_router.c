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

void handle_arp_request(struct sr_instance *sr, struct sr_ethernet_hdr *ethernet_header,
        struct sr_arphdr *arp_header, char *interface);

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
    memcpy(header, packet, 14);
    header->ether_type = htons(header->ether_type);

    // Determine proper routing behavior based on ether_type
    switch(header->ether_type) {
        case ETHERTYPE_ARP:
            {
                // Unpack the ARP header
                struct sr_arphdr *arp_header = malloc(sizeof(struct sr_arphdr));
                memcpy(arp_header, packet + 14, len);
                arp_header->ar_op = ntohs(arp_header->ar_op);

                // Check the ARP opcode
                switch(arp_header->ar_op) {
                    case ARP_REQUEST:
                        handle_arp_request(sr, header, arp_header, interface);
                        break;
                    case ARP_REPLY:
                        printf("IT's an ARP reply!\n");
                        break;
                }
                break;
            }
        case ETHERTYPE_IP:
            {
                // TODO
                printf("\tIt's an IP packet!\n");
                break;
            }
        default:
            {
                printf("\tIt's an unknown packet type (ether_type = 0x%X)\n", header->ether_type);
                break;
            }
    }

} /* end sr_ForwardPacket */

void handle_arp_request(struct sr_instance *sr, struct sr_ethernet_hdr *ethernet_header,
        struct sr_arphdr *arp_header, char *interface) {
    printf("\tIt's an ARP request!\n");

    // Create ARP reply :)
    struct sr_arphdr arp_reply;
    memcpy(&arp_reply, arp_header, sizeof(struct sr_arphdr));
    arp_reply.ar_op = htons(ARP_REPLY);
    memcpy(&arp_reply.ar_sha, sr_get_interface(sr, interface)->addr, ETHER_ADDR_LEN);
    memcpy(&arp_reply.ar_tha, &(arp_header->ar_sha), ETHER_ADDR_LEN);
    memcpy(&arp_reply.ar_sip, &(arp_header->ar_tip), sizeof(uint32_t));
    memcpy(&arp_reply.ar_tip, &(arp_header->ar_sip), sizeof(uint32_t));

    // Get the interface address
    struct sr_if* iface = sr_get_interface(sr, interface);
    if ( iface == 0 ) {
        fprintf( stderr, "** Error, interface %s, does not exist\n", interface);
    }

    // Create the ethernet header
    struct sr_ethernet_hdr eth_reply;
    memcpy(&eth_reply.ether_dhost, &ethernet_header->ether_shost, ETHER_ADDR_LEN);
    memcpy(&eth_reply.ether_shost, &iface->addr, ETHER_ADDR_LEN);
    eth_reply.ether_type = htons(ETHERTYPE_ARP);

    // Wrap ARP packet in Ethernet header, add to buffer
    uint8_t *buf = malloc(sizeof(eth_reply) + sizeof(arp_reply));
    memcpy(buf, &eth_reply, sizeof(eth_reply));
    memcpy(buf + sizeof(eth_reply), &arp_reply, sizeof(arp_reply));

    // Send the packet
    sr_send_packet(sr, buf, sizeof(eth_reply) + sizeof(arp_reply), interface);
}


/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/
