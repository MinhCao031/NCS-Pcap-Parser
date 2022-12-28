#ifndef HASH_TABLE_H
#define HASH_TABLE_H

#include "flow_api.h"
#include "parsers.h"
#include "log.h"

typedef struct {
  size_t size;
  Node **lists;
} HashTable;

// according protocol,vv the way to insert a node into hash table may be
// different
enum InsertAlgorihm { FIRST = 0, LAST = 1, ASC = 2, DESC = 3 };

// Hash function
uint hash(uint64_t x, size_t len);
void free_hash_table(HashTable table);
HashTable create_hash_table(size_t size);
// insert a new flow into the hash table
void insert_new_flow(HashTable table, Node *const flow_node);

// Insert a packet into a flow
void insert_to_flow(Node *const pkt_node, enum InsertAlgorihm insert_type,
                    Node **flow_direction, FILE* fptr);

// search for a flow with the given key
flow_base_t *search_flow(HashTable const table, uint64_t key, FILE* fptr);

// delete a flow with the given key
void delete_flow(HashTable table, uint64_t key);

// Get number of packets in hash table
uint count_packets(HashTable const table);

// get number of flows in hash table
uint count_flows(HashTable const table);

// get number of nodes in a flow
uint get_flow_size(flow_base_t const *flow);

// pop head packet data from a flow
parsed_payload pop_head_payload(Node **flow_diection);

// free a payload node and it's data in a flow
void free_payload_node(Node *payload_node);

// free all payload nodes in a flow and free flow
void free_flow_direction(Node *flow_direction);

#endif
