#ifndef HASH_TABLE_H
#define HASH_TABLE_H

#include "flow_api.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

typedef struct {
  guint32 size;
  Node **lists;
} HashTable;

// according to protocol
// the way to insert a node into hash table may be different
enum InsertAlgorihm { FIRST = 0, LAST = 1, ASC = 2, DESC = 3 };

// Hash function
guint32 hash(guint64 x, guint64 len);

// free a hashtable
void free_hash_table(HashTable table);

// create a hash table
HashTable create_hash_table(guint64 size);

// insert a new flow into the hash table
void insert_new_flow(HashTable table, Node *const flow_node);

// Insert a packet into a flow
void insert_to_flow(Node *const pkt_node, enum InsertAlgorihm insert_type, flow_base_t* flow_ptr, FILE* stream);

// search for a flow with the given key
flow_base_t *search_flow(HashTable const table, guint64 key, FILE* stream);

// delete a flow with the given key
void delete_flow(HashTable table, guint64 key);

// Get number of packets in hash table
guint32 count_packets(HashTable const table);

// get number of flows in hash table
guint32 count_flows(HashTable const table);

// get number of nodes in a flow
guint32 get_flow_size(flow_base_t const *flow);

// free a payload node and it's data in a flow
void free_payload_node(Node *payload_node);

// free all payload nodes in a flow and free flow
void free_flow_direction(Node *flow_direction);

#endif
