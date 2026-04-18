#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "protocols.h"
#include "queue.h"
#include "lib.h"
#include "trie.h"

int get_prefix_len(uint32_t mask) {
    int len = 0;
    // I worked on a copy so I do not modify the original
    uint32_t m = mask;
    // Iterate through all of the bits
    while (m != 0) {
        // Counting the bits
        len++;

        // Shift to the left to calculate the rest number of bits
        m = (m << 1);
    }
    return len;
}

struct trie_node *trie_new_node() {
    // Zero the node because if child pointers have garbage values,
    // trie_insert would follow them and crash
    struct trie_node *node = calloc(1, sizeof(struct trie_node));
    DIE(!node, "calloc trie");
    return node;
}

void trie_insert(struct trie_node *root, struct route_table_entry *entry) {
    // Starting from the root
    struct trie_node *node = root;

    // get the prefix and the mask and convert it
    uint32_t prefix = ntohl(entry->prefix);
    uint32_t mask = ntohl(entry->mask);

    // Count prefix length from the mask
    int prefix_len = get_prefix_len(mask);

    // I traversed the trie one bit at a time, from the MSB down
    // it is 32 - prefix_len so I can run prefix_len times
    for (int i = 31; i >= 32 - prefix_len; i--) {
        // extract bit i
        int bit = (prefix >> i) & 1;

        // if the bit is zero it means we're going left
        // and we allocate the new node
        if (bit == 0) {
            if (!node->child_0)
                node->child_0 = trie_new_node();
            node = node->child_0;

        // if the bit is 1, we're going right and we allocate
        // the new node
        } else if (bit == 1) {
            if (!node->child_1)
                node->child_1 = trie_new_node();
            node = node->child_1;
        }
    }
    // The node points to the leaf for this prefix
    // Storing the route entry here to mark the area
    // as a valid routing destination
    node->route = entry;
}

struct route_table_entry *trie_lookup(struct trie_node *root, uint32_t dest_ip) {
    // Extracting the root
    struct trie_node *node = root;

    // Initialize the best route
    struct route_table_entry *best = NULL;

    // Converting dest IP to host byte order so bit 31 is MSB
    uint32_t dest = ntohl(dest_ip);

    // Traversing all 32 bits and checking if we're getting
    // out of the trie
    for (int i = 31; i >= 0 && node; i--) {
        // Extracting bit i
        int bit = (dest >> i) & 1;
        if (bit == 0) {
            node = node->child_0;
        } else {
            node = node->child_1;
        }

        // If the node exists and has a route stored
        // that means it has a valid prefix match and 
        // we update the best route
        if (node && node->route)
            best = node->route;
    }
    return best;
}