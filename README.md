# Dataplane Router

**Author:** Vlad Parau

A software dataplane router implementation in C, supporting IPv4 forwarding, ARP resolution, ICMP echo and error handling, and efficient Longest Prefix Match using a binary trie. Tested on a Mininet-based topology.

---

## Project Structure

```text
.
├── checker/
│   ├── checker.py       # Automated test runner
│   ├── checker.sh       # Shell wrapper for checker
│   ├── info.py          # Topology info utilities
│   ├── tests.py         # Test definitions
│   └── topo.py          # Mininet topology definition
├── include/
│   ├── lib.h            # Interface for packet I/O helpers
│   ├── list.h           # Linked list interface
│   ├── protocols.h      # Ethernet, IP, ARP, ICMP header structs
│   ├── queue.h          # Queue interface
│   └── trie.h           # Binary trie interface for LPM
├── lib/
│   ├── lib.c            # Packet send/receive and interface helpers
│   ├── list.c           # Linked list implementation
│   ├── queue.c          # Queue implementation
│   └── trie.c           # Binary trie implementation for LPM
├── .gitignore
├── create_archive.sh    # Script to create submission archive
├── Makefile
├── README.md
├── router.c             # Main router dataplane logic
├── router0              # Compiled router binary (instance 0)
├── router1              # Compiled router binary (instance 1)
├── rtable0.txt          # Static routing table for router 0
└── rtable1.txt          # Static routing table for router 1
```

---

## Overview

This project implements the dataplane of a software router in C. The router receives raw Ethernet frames, parses their headers, and decides how to process each packet — either handling it locally or forwarding it to the next hop.

The router operates in a Mininet topology with multiple hosts and routers connected across different subnets. It is built around a packet processing loop that dispatches each received frame to the appropriate handler based on EtherType.

---

## Supported Protocols

### Ethernet
The router inspects the EtherType field of every received frame to distinguish between IPv4 and ARP payloads and dispatches accordingly.

### IPv4
IPv4 packets are validated via checksum, checked against the router's own interfaces, and either processed locally or forwarded. TTL is decremented before forwarding and the checksum is recomputed. Packets with invalid checksums or expired TTL are handled with appropriate ICMP messages.

### ARP
ARP is used to dynamically resolve the MAC address of the next hop. The router answers ARP Requests addressed to its own interfaces and learns MAC addresses from incoming ARP Replies. Packets waiting for ARP resolution are temporarily held in a queue.

### ICMP
The router supports four ICMP scenarios:
- **Echo Reply (Type=0)** — response to pings addressed directly to the router
- **Echo Request (Type=8)** — detected and triggers Echo Reply generation
- **Time Exceeded (Type=11, Code=0)** — sent when TTL expires during forwarding
- **Destination Unreachable (Type=3, Code=0)** — sent when no route is found

---

## Implementation Details

### IP Forwarding (`handle_ip`)
The main IPv4 processing function performs the following steps in order:
1. Validate the IP checksum — drop the packet if incorrect
2. Check if the destination belongs to the router itself via `check_router_for_destination()`
3. If it is a local ICMP Echo Request, generate an Echo Reply and return
4. Look up the best route via `get_best_route()` using the binary trie
5. If no route exists, send ICMP Destination Unreachable and return
6. If TTL <= 1, send ICMP Time Exceeded and return
7. Decrement TTL and recompute the IP checksum
8. Look up the next-hop MAC in the ARP table via `get_arp_entry()`
9. If the MAC is unknown, call `handle_arp_cache_miss()` and return
10. Update Ethernet headers and forward the packet on the correct interface

### Longest Prefix Match (`get_best_route`)
Route lookup uses a **binary trie** built from `rtable.txt` at startup. Each destination IP is matched bit by bit from MSB to LSB. This gives O(32) lookup time regardless of the number of routes, compared to O(n) for a linear scan.

### ARP Cache Miss (`handle_arp_cache_miss`)
When the next-hop MAC is not in the ARP table, the packet is copied into a `queued_packet` struct and placed in the `waiting_packets` queue. A broadcast ARP Request is then sent on the outgoing interface. Once the ARP Reply arrives and the MAC is learned, the queue is drained and all resolvable packets are transmitted.

### ARP Reply Handling (`handle_arp_reply`)
The sender IP and MAC from the ARP Reply are added to `arp_table`. The `waiting_packets` queue is then fully drained into an auxiliary queue: packets whose next hop can now be resolved are forwarded immediately; the rest are moved back to the main queue.

### ICMP Generation (`handle_icmp`)
A unified function handles both Echo Reply and error generation via a `mode` parameter:
- **ICMP_ECHO_REPLY** — copies ID, sequence number, and payload from the original request; sets source IP to the pinged interface
- **ICMP_ERROR** — embeds the original IP header plus first 8 bytes of the original payload as the ICMP error payload, per RFC 792

All generated packets have their IP and ICMP checksums computed from scratch.

---

## Key Functions

| Function | Description |
|---|---|
| `get_best_route(ip_dest)` | Trie-based LPM route lookup |
| `get_arp_entry(given_ip)` | Linear ARP table search |
| `check_router_for_destination(dest_ip)` | Checks if destination matches a router interface |
| `handle_arp_request(...)` | Builds and sends ARP Reply in-place |
| `handle_arp_reply(...)` | Updates ARP table and drains waiting queue |
| `handle_arp_cache_miss(...)` | Queues packet and sends broadcast ARP Request |
| `handle_icmp(...)` | Generates ICMP Echo Reply or error packet |
| `handle_ip(...)` | Main IPv4 processing and forwarding logic |
| `handle_arp(...)` | Dispatches ARP packets to request/reply handlers |

---

## How to Build and Run

```bash
# Build
make

# Start the Mininet topology
sudo python3 checker/topo.py

# Run the routers (from the Mininet terminal or separate xterms)
make run_router0
make run_router1

# From host h0 (xterm):
ping -c 3 192.168.0.1       # ICMP Echo Reply
ping -c 3 192.168.1.2       # IP Forwarding across subnets
ping -c 1 -t 1 h1           # ICMP Time Exceeded (TTL=1)
ping -c 1 10.0.0.1          # ICMP Destination Unreachable

# Run automated tests
bash checker/checker.sh
```

---

## Notes

- The ARP table starts empty and is populated entirely at runtime through ARP exchanges.
- The `waiting_packets` queue uses a drain-and-requeue pattern because entries cannot be removed mid-queue.
- The binary trie stores pointers to `rtable` entries to avoid data duplication.
- All multi-byte header fields are converted between host and network byte order using `htons()`, `ntohs()`, `htonl()`, `ntohl()` as required.
- Packets are received and processed in network byte order throughout.
