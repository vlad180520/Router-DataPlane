#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "protocols.h"
#include "queue.h"
#include "lib.h"
#include "trie.h"

// I stored a macro for the broadcast address used to
// send the ARP to all of the routers
#define BROADCAST_MAC_ADDRESS  {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

// this is a code for the function to process the error and the echo reply
// (I made this because it is redundant to create two separated functions)
#define ICMP_ERROR 0
#define ICMP_ECHO_REPLY 1

/* Routing table */
struct route_table_entry *rtable;
int rtable_len;

/* ARP table */
struct arp_table_entry *arp_table;
int arp_table_len;

// This is the root for the trie tree
struct trie_node *trie_root;

// The queue for the ARP
queue waiting_packets;

// struct for the packet to store it (and eventually send it)
struct queued_packet {
    char *packet_header;
    size_t len;
	// the route we use to send the packet
    struct route_table_entry *route;
};

/*
 Returns a pointer (eg. &rtable[i]) to the best matching route, or NULL if there
 is no matching route.
*/
struct route_table_entry *get_best_route(uint32_t ip_dest) {
	return trie_lookup(trie_root, ip_dest);
}

struct arp_table_entry *get_arp_entry(uint32_t given_ip) {
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
// This function is used when an ARP reply arrives
void handle_arp_reply(char* packet) {
	// Skip the ethernet header to reach the ARP header
	struct arp_hdr* arp_header = (struct arp_hdr*)(packet + sizeof(struct ether_hdr));

	// Store the sender's IP address from the ARP reply into the next
	// free slot in our ARP table
	// sprotoa = sender protocol address = sender IP
	arp_table[arp_table_len].ip = arp_header->sprotoa;

	// Store the sender's MAC address into the same ARP table slot
	memcpy(arp_table[arp_table_len].mac, arp_header->shwa, sizeof(arp_header->shwa));

	// Increasing the size of the table (cause we added one more entry)
	arp_table_len++;

	// Created a temporary auxiliary queue
	// We can't remove entries mid-queue, so we drain waiting_packets
	// entirely, send the ones we can now resolve, and reput the elements
	// in the queue
	queue aux = create_queue();

	// Iterating through all of the packets sitting the queue
	while (!queue_empty(waiting_packets)) {
		// Dequeue the next waiting packet
		struct queued_packet* qp = queue_deq(waiting_packets);

		// checking if the ARP table now has a MAC entry for the
		// packet next hop
		struct arp_table_entry* found = get_arp_entry(qp->route->next_hop);

		// if it has, we can send it
		if (found) {
			// we process the details, placing them accordingly, and
			// the send the packet to the accordingly MAC address
			struct ether_hdr* eth_hdr = (struct ether_hdr*)qp->packet_header;
			memcpy(eth_hdr->ethr_dhost, found->mac, sizeof(found->mac));
			get_interface_mac(qp->route->interface, eth_hdr->ethr_shost);
			send_to_link(qp->len, qp->packet_header, qp->route->interface);

			// freeing the packet cause we sent it
			free(qp->packet_header);
			// freeing the queued packet itself
            free(qp);
		} else {
			// Otherwise we still do not know the MAC address and
			// we need to keep waiting
			queue_enq(aux, qp);
		}
	}

	// aux contains the packets that are still waiting
	waiting_packets = aux;
}

void handle_arp_request(int interface, char* packet, size_t packet_len) {
	struct ether_hdr* eth_hdr = (struct ether_hdr*)packet;
	struct arp_hdr* arp_header = (struct arp_hdr*)(packet + sizeof(struct ether_hdr));

	// Replied only if the ARP is asking for this interface's IP
	if (arp_header->tprotoa != inet_addr(get_interface_ip(interface))) {
		return;
	}

	//Changed opcode from 1 to 2 so that the
	// sender knows this request has answered
	arp_header->opcode = htons(2);

	// now the sender becomes the target (we copy the MAC address)
	memcpy(arp_header->thwa, arp_header->shwa, sizeof(arp_header->shwa));

	// and we copy the ip address also
	arp_header->tprotoa = arp_header->sprotoa;

	// I am reading the interface MAC address and writing it to the sender
	// hardware address
	get_interface_mac(interface, arp_header->shwa);

	// we send need to obtain the interface ip address and place
	// it to the sender because we send the packet throught the interface
	arp_header->sprotoa = inet_addr(get_interface_ip(interface));

	// The reply goes back to the original requester
	memcpy(eth_hdr->ethr_dhost, eth_hdr->ethr_shost, sizeof(eth_hdr->ethr_shost));

	// set our interface MAC as the ethernet source address
	get_interface_mac(interface, eth_hdr->ethr_shost);

	// send the modified packet back on the same interface it arrived on
	send_to_link(packet_len, packet, interface);
}

void handle_arp(int interface, char* packet, size_t packet_len) {
	struct arp_hdr* arp_header = (struct arp_hdr*)(packet + sizeof(struct ether_hdr));

	// handle the arp based on the code in the header
	if(ntohs(arp_header->opcode) == 1) {
		handle_arp_request(interface, packet, packet_len);
	} else if(ntohs(arp_header->opcode) == 2) {
		handle_arp_reply(packet);
	}
}
// I used this function when we need to forward a packet but
// don't know the MAC address of the next hop yet
void handle_arp_cache_miss(struct route_table_entry* best_route, char* packet, size_t packet_len) {
	// Allocated the wrapper struct to hold this packet while it waits
	struct queued_packet* qp = malloc(sizeof(struct queued_packet));
	DIE(qp == NULL, "malloc qp cache miss");

	// alocated the header to hold the copy of the packet header
	qp->packet_header = malloc(packet_len);
	DIE(qp->packet_header == NULL, "malloc packet header");

	// copying the packet bytes into our buffer
	memcpy(qp->packet_header, packet, packet_len);
	qp->len = packet_len;

	// the route is the best route
	qp->route = best_route;

	// push the queued packet into the queue
	queue_enq(waiting_packets, qp);

	// allocated the buffer for the ethernet and the arp payload
	char arp_request[sizeof(struct ether_hdr) + sizeof(struct arp_hdr)];

	// zero the buffer for the garbage security
	memset(arp_request, 0, sizeof(arp_request));

	// set up the pointers for the buffer
	struct ether_hdr *request_eth = (struct ether_hdr *)arp_request;
    struct arp_hdr *request_arp = (struct arp_hdr *)(arp_request + sizeof(struct ether_hdr));

	// the source MAC is this router's interface (we are the sender)
	get_interface_mac(best_route->interface, request_eth->ethr_shost);

	// processed the broadcast address as a vector
	// but it is a variable in reality
	uint8_t broadcast[] = BROADCAST_MAC_ADDRESS;

	// sending ARP request with broadcast address because
	// we do not know the dest MAC and we need to search it
    memcpy(request_eth->ethr_dhost, broadcast, sizeof(broadcast));

	// telling the receiver this is an ARP frame
    request_eth->ethr_type = htons(ETHERTYPE_ARP);

	// the MAC address the receiver should expect is ethernet(1)
	request_arp->hw_type = htons(1);

	// the protocol type is IP
	request_arp->proto_type = htons(ETHERTYPE_IP);
	// MAC ADDRESS SIZE
	request_arp->hw_len = 6;
    // IP address size
	request_arp->proto_len = 4;
	// the opcode is the request code
	request_arp->opcode = htons(1);

	// the sender MAC is this router's interface MAC
	get_interface_mac(best_route->interface, request_arp->shwa);

	// sender IP is this router interface IP
	request_arp->sprotoa = inet_addr(get_interface_ip(best_route->interface));

	// target MAC has only 0 because we do not know it yet
	memset(request_arp->thwa, 0, sizeof(request_arp->thwa));

	// target IP is the next hop IP we need to resolve
	request_arp->tprotoa = best_route->next_hop;

	// broadcasted the ARP request on the interface that leads to
	// the next hop
	// only the one with next hop IP addr will reply
	send_to_link(sizeof(arp_request), arp_request, best_route->interface);
}

void handle_icmp(struct ether_hdr* eth_hdr, struct ip_hdr* ip_hdr, int interface, uint8_t mtype, uint8_t mcode, int mode) {
	// I allocated a buffer for the reply packet (we do not modify the original)
	char reply[MAX_PACKET_LEN];
	//Zero the buffer cause it is good practice (for the garbage)
	memset(reply, 0, sizeof(reply));

	//I defined the headers so that it would be easier to work with (I know 
	// exactly where to place and what)
	struct ether_hdr* reply_eth = (struct ether_hdr*)reply;
	struct ip_hdr* reply_ip = (struct ip_hdr*)(reply + sizeof(struct ether_hdr));
	struct icmp_hdr* reply_icmp = (struct icmp_hdr*)(reply + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));

	//Ethernet Header
	// The reply goes back to the sender (so the destination MAC becomes the initial sender MAC)
	memcpy(reply_eth->ethr_dhost, eth_hdr->ethr_shost, sizeof(eth_hdr->ethr_shost));

	// I got the interface of the sender (because the source MAC is the interface MAC)
	get_interface_mac(interface, reply_eth->ethr_shost);

	// I am telling the receiver this is an IP packet
	reply_eth->ethr_type = htons(ETHERTYPE_IP);
	
	//IP Header
	reply_ip->ver = 4;
	reply_ip->ihl = 5;

	reply_ip->tos = 0;

	reply_ip->id = htons(4);
	reply_ip->frag = 0;

	// Set a standard TTL value
	reply_ip->ttl = 64;

	// Set the protocol to ICMP (it is telling IP that it uses ICMP)
	reply_ip->proto = IPPROTO_ICMP;

	// Destination IP = the original sender's IP (send error back to them)
    reply_ip->dest_addr = ip_hdr->source_addr;

	if (mode == ICMP_ECHO_REPLY) {
		// Source is the router IP that was pinged
		reply_ip->source_addr = ip_hdr->dest_addr;

		// Same total length as the request
		reply_ip->tot_len = ip_hdr->tot_len;
	} else if (mode == ICMP_ERROR) {
		// Source IP = this router's interface IP (we are the ones sending the error)
		reply_ip->source_addr = inet_addr(get_interface_ip(interface));

		// IP header + ICMP header + original IP header + 8 bytes of original payload
		reply_ip->tot_len = htons(sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + sizeof(struct ip_hdr) + 8);
	}

	// Computed the checksum 
	reply_ip->checksum = 0;
    reply_ip->checksum = htons(checksum((uint16_t *)reply_ip, sizeof(struct ip_hdr)));

	// ICMP header

	// Set the ICMP type and code passed as parameters
    // type=11, code=0 - Time Exceeded (TTL expired)
    // type=3, code=0 - Destination Unreachable (no route found)
    reply_icmp->mtype = mtype;
    reply_icmp->mcode = mcode;

	if (mode == ICMP_ECHO_REPLY) {
		// Extract the icmp header from the IP header
		struct icmp_hdr *req_icmp = (struct icmp_hdr *)((uint8_t *)ip_hdr + sizeof(struct ip_hdr));

		// Preserve the echo ID and sequence number from the request
        reply_icmp->un_t.echo_t.id  = req_icmp->un_t.echo_t.id;
        reply_icmp->un_t.echo_t.seq = req_icmp->un_t.echo_t.seq;

		// Calculating the payload length
		size_t icmp_payload_len = ntohs(ip_hdr->tot_len) - sizeof(struct ip_hdr) - sizeof(struct icmp_hdr);
		// Copying the payload (+1 is because the size of the ICMP header is 1 byte)
		memcpy((uint8_t *)(reply_icmp + 1), (uint8_t *)(req_icmp + 1), icmp_payload_len);

		// Calculating the checksum
		// The checksum calculates using the ICMP message also
		reply_icmp->check = 0;
		size_t icmp_total = sizeof(struct icmp_hdr) + icmp_payload_len;
		reply_icmp->check = htons(checksum((uint16_t *)reply_icmp, icmp_total));

		// The reply has the same total size as the original request 
		// because I am echoing back the same payload. tot_len already
		// includes the IP header + ICMP header + payload, so I just add
		// the Ethernet header on top to get the full frame length to send.
		size_t reply_len = sizeof(struct ether_hdr) + ntohs(ip_hdr->tot_len);
		send_to_link(reply_len, reply, interface);

	} else if (mode == ICMP_ERROR) {
		// Zeroed checksum before computing it
		reply_icmp->check = 0;
		
		// (reply_icmp + 1) advances the pointer past the ICMP header
		// to the byte immediately after it, where the payload starts
		uint8_t *payload = (uint8_t *)(reply_icmp + 1);
		memcpy(payload, ip_hdr, sizeof(struct ip_hdr) + 8);
		
		// Computed the checksum over the entire ICMP header
		reply_icmp->check = htons(checksum((uint16_t *)reply_icmp, sizeof(struct icmp_hdr) + sizeof(struct ip_hdr) + 8));
		size_t reply_len = sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + sizeof(struct ip_hdr) + 8;
		
		// Sent the reply on the same interface the package arrived
		send_to_link(reply_len, reply, interface);
	}

}

void handle_ip(int interface, char* packet, size_t packet_len) {
	struct ether_hdr *eth_hdr = (struct ether_hdr *) packet;
	struct ip_hdr *ip_hdr = (struct ip_hdr *)(packet + sizeof(struct ether_hdr));
	uint16_t packet_checksum = ip_hdr->checksum;

		// computed the checksum
		ip_hdr->checksum = 0;
		int sum_ok = (checksum((uint16_t *)ip_hdr, sizeof(struct ip_hdr)) == ntohs(packet_checksum));
		if (!sum_ok) {
			printf("Bad checksum\n");
			return;
		}
		// Restore the original checksum (we didn't modified the IP header yet)
		ip_hdr->checksum = packet_checksum;

		// Check if the packet is destined for the router itself
		if (check_router_for_destination(ip_hdr->dest_addr)) {
			if (ip_hdr->proto == IPPROTO_ICMP) {
				// The ICMP header starts immediately after the IP header
				struct icmp_hdr *icmp_h = (struct icmp_hdr *)((uint8_t *)ip_hdr + sizeof(struct ip_hdr));
				// If the type is 8, send the echo reply
				if (icmp_h->mtype == 8) {
					handle_icmp(eth_hdr, ip_hdr, interface, 0, 0, ICMP_ECHO_REPLY);
				}
			}
			return;
		}

		// getting the best route
		struct route_table_entry *best_route = get_best_route(ip_hdr->dest_addr);
		if(best_route == NULL) {
			// if no route is found we send an ICMP Destination Unreachable
			// back to the original sender
			handle_icmp(eth_hdr, ip_hdr, interface, 3, 0, ICMP_ERROR);
			return;
		}

		// if the expired we need to send an ICMP message Time Exceeded
		if(ip_hdr->ttl <= 1) {
			handle_icmp(eth_hdr, ip_hdr, interface, 11, 0, ICMP_ERROR);
			return;
		}

		// we decrement the ttl by 1 as required for IP
		ip_hdr->ttl--;

		// we recalculate the checksum because we modified the ttl
		ip_hdr->checksum = 0;
		ip_hdr->checksum = htons(checksum((uint16_t*) ip_hdr, sizeof(struct ip_hdr)));

		// 
		struct arp_table_entry *arp_entry = get_arp_entry(best_route->next_hop);
		if (arp_entry == NULL) {
			//We don't know the MAC address of the next hop yet.
         	//Queue the packet and send an ARP request to find out.
         	//The packet will be sent once the ARP reply arrives.
			handle_arp_cache_miss(best_route, packet, packet_len);
			return;
		}

		//handle ip forward
		memcpy(eth_hdr->ethr_dhost, arp_entry->mac, sizeof(arp_entry->mac));
		get_interface_mac(best_route->interface, eth_hdr->ethr_shost);
		send_to_link(packet_len, packet, best_route->interface);
}

int main(int argc, char *argv[])
{
	char packet[MAX_PACKET_LEN];

	// Do not modify this line
	// Sets the sockets (there are argc - 2 sockets because the first 2 are the binary
	// and the routing table)
	init(argv + 2, argc - 2);

	/* Code to allocate the MAC and route tables */
	rtable = malloc(sizeof(struct route_table_entry) * 100000);
	/* DIE is a macro for sanity checks */
	DIE(rtable == NULL, "memory");

	arp_table = malloc(sizeof(struct arp_table_entry) * 100000);
	DIE(arp_table == NULL, "memory");
	
	/* Read the static routing table and the MAC table */
	rtable_len = read_rtable(argv[1], rtable);
	arp_table_len = 0;
	// Create the empty root node (the starting point of the trie)
	trie_root = trie_new_node();

	// Insert every route from rtable.txt into the trie
	for (int i = 0; i < rtable_len; i++)
		trie_insert(trie_root, &rtable[i]);

	waiting_packets = create_queue();

	while (1) {
		int interface;
		size_t packet_len;
		// TODO: Implement the router forwarding logic
	
		/* Note that packets received are in network order,
			any header field which has more than 1 byte will need to be conerted to
			host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
			sending a packet on the link, */
		
		interface = recv_from_any_link(packet, &packet_len);
		DIE(interface < 0, "recv_from_any_links");
		printf("We have received a packet\n");

		struct ether_hdr *eth_hdr = (struct ether_hdr *) packet;

		// handle arp and ip based on the type
		if (eth_hdr->ethr_type == htons(ETHERTYPE_IP)) {
			handle_ip(interface, packet, packet_len);
		} else if (eth_hdr->ethr_type == htons(ETHERTYPE_ARP)) {
			handle_arp(interface, packet, packet_len);
		}
	}

	return 0;
}
