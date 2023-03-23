#ifndef HANDLER_H
#define HANDLER_H

#include "hash_table.h"

// get key from IPs & ports
uint64_t get_flow_key(uint64_t x1, uint64_t x2, uint64_t y1, uint64_t y2);

// create a node (linked list) of flow
Node *create_flow_node(uint64_t key, flow_base_t flow, FILE* stream);

// create a node of payload
Node *create_payload_node(parsed_packet pkt, bool is_pkt_up);

// create new flow from packet info and initialize flow direction
flow_base_t create_flow(parsed_packet pkt, FILE* stream);

// Get direction of a packet by compare src ip of the packet with the flow
bool is_packet_up(flow_base_t const *flow, parsed_packet pkt);

// classify and insert a new packet into hash table
void insert_packet(HashTable table, parsed_packet pkt, FILE* stream);

// insert tcp packet to flow
void insert_tcp_pkt(HashTable table, uint64_t flow_key, parsed_packet pkt, FILE* stream);

// insert udp packet to flow
void insert_udp_pkt(HashTable table, uint64_t flow_key, parsed_packet pkt, FILE* stream);

// iterate through all ID in hashtable to print
void print_hashtable(HashTable const table, FILE* stream);

// iterate through all flows in list to print
void print_flows(Node const *const head, FILE* stream);

// print all payloads in a flow
void print_flow(flow_base_t flow, FILE* stream);

// print payload from pointer of char with given size (to prevent stopping at '\0')
void print_payload(u_char const *payload, int32_t payload_size, FILE* stream);

// print payload to match the data on wireshark
void print_hex_ascii_line(u_char const *const payload, int32_t len, int32_t offset, FILE* stream);

// Get payloads of a single flow direction and concatenate them into a single string (pointer of char)
char* payload_to_string(Node* flow_direction, uint32_t len_need);

/* Convert payload string to an array of printable characters, will convert:
 *
 * - Printable characters   -> Keep
 * - '\t', '\n', '\r'       -> Keep
 * - '\v', '\f'             -> '\n'
 * - Others                 -> '.'
 */
char* convert_payload(char* payload, uint32_t length);

#endif
