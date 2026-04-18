#include <stdint.h>

#include "lib.h"

struct trie_node {
    struct route_table_entry *route;
    // left is bit 0, right is bit 1
    struct trie_node *child_0, *child_1;
};

void trie_insert(struct trie_node *root, struct route_table_entry *entry);
struct route_table_entry *trie_lookup(struct trie_node *root, uint32_t dest_ip);
struct trie_node *trie_new_node();