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

#include <stdio.h>
#include <assert.h>
#include <strings.h>
#include <string.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"

#include "protocol.h"

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

    printf("*** -> Received packet of length %d \n",len);

    // Deconstruct the packet's ethernet header
    struct sr_ethernet_hdr header;
    memcpy(&header, packet, 14);
    header.ether_type = htons(header.ether_type);

    // Determine proper routing behavior based on ether_type
    switch(header.ether_type) {
        case ETHERTYPE_ARP:
            {
                // Unpack the ARP header
                struct sr_arphdr arp_header;
                memcpy(&arp_header, packet + 14, len);
                arp_header.ar_op = ntohs(arp_header.ar_op);

                // Check the ARP opcode
                if(arp_header.ar_op == ARP_REQUEST) {
                    printf("\tIt's an ARP request!\n");
                } else if(arp_header.ar_op == ARP_REPLY) {
                    printf("\tIt's an ARP reply!\n");
                }
                break;
            }
        case ETHERTYPE_IP:
            {
                printf("\tIt's an IP packet!\n");
                break;
            }
        default:
            {
                printf("\tIt's an unknown packet type (ether_type = 0x%X)\n", header.ether_type);
                break;
            }
    }

}/* end sr_ForwardPacket */


/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/
