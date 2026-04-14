#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "protocols.h"
#include "queue.h"
#include "lib.h"

/* Routing table */
struct route_table_entry *rtable;
int rtable_len;

/* ARP table */
struct arp_table_entry *arp_table;
int arp_table_len;

/*
 Returns a pointer (eg. &rtable[i]) to the best matching route, or NULL if there
 is no matching route.
*/
struct route_table_entry *get_best_route(uint32_t ip_dest) {
	/* TODO 2.2: Implement the LPM algorithm */
	/* We can iterate through rtable for (int i = 0; i < rtable_len; i++). Entries in
	 * the rtable are in network order already */

	struct route_table_entry *best = NULL;

	for(int i = 0; i < rtable_len; i++) {
		if ((ip_dest & rtable[i].mask) == rtable[i].prefix) {
			if (best == NULL || ntohl(rtable[i].mask) > ntohl(best->mask)) {
				best = &rtable[i];
			}
		}
	}
	return best;
}

struct arp_table_entry *get_arp_entry(uint32_t given_ip) {
	/* TODO 2.4: Iterate through the ARP table and search for an entry
	 * that matches given_ip. */

	/* We can iterate through the arp_table for (int i = 0; i <
	 * arp_table_len; i++) */

	for (int i = 0; i < arp_table_len; i++) {
		if(arp_table[i].ip == given_ip) {
			return &arp_table[i];
		}
	}
	
	return NULL;
}

// Function to check if the current router is the destination for a host
int check_router_for_destination(uint32_t dest_ip) {
	// we iterate through the interfaces of the router
	for (int i = 0; i < ROUTER_NUM_INTERFACES; i++) {
		if (dest_ip == inet_addr(get_interface_ip(i))) {
			return 1;
		}
	}

	return 0;
}

int main(int argc, char *argv[])
{
	char packet[MAX_PACKET_LEN];

	// Do not modify this line
	// Sets the sockets (there are argc - 2 sockets because the first 2 are the binary
	// and the routing table)
	init(argv + 2, argc - 2);

	/* Code to allocate the MAC and route tables */
	rtable = malloc(sizeof(struct route_table_entry) * 100);
	/* DIE is a macro for sanity checks */
	DIE(rtable == NULL, "memory");

	arp_table = malloc(sizeof(struct arp_table_entry) * 100);
	DIE(arp_table == NULL, "memory");
	
	/* Read the static routing table and the MAC table */
	rtable_len = read_rtable(argv[1], rtable);
	arp_table_len = parse_arp_table("arp_table.txt", arp_table);

	while (1) {

		size_t interface;
		size_t packet_len;

		interface = recv_from_any_link(packet, &packet_len);
		DIE(interface < 0, "recv_from_any_links");
		printf("We have received a packet\n");

		struct ether_hdr *eth_hdr = (struct ether_hdr *) packet;
		struct ip_hdr *ip_hdr = (struct ip_hdr *)(packet + sizeof(struct ether_hdr));

		/* Check if we got an IPv4 packet */
		if (eth_hdr->ethr_type != ntohs(ETHERTYPE_IP)) {
			printf("Ignored non-IPv4 packet\n");
			continue;
		}

		uint16_t packet_checksum = ip_hdr->checksum;

		ip_hdr->checksum = 0;
		int sum_ok = (ip_checksum((uint16_t *)ip_hdr, sizeof(struct ip_hdr)) == ntohs(packet_checksum));
		if (!sum_ok) {
			printf("Bad checksum\n");
			continue;
		}

		ip_hdr->checksum = packet_checksum;


    // TODO: Implement the router forwarding logic

    /* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */


	}
}

