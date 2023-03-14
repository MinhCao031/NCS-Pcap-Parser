#ifndef HANDLER_H
#define HANDLER_H


#include "hash_table.h"
#include "parsers.h"
#include "log.h"
#include <time.h>
#include <sys/time.h>

extern uint32_t inserted_packets;
extern uint32_t filtered_packets;

// get key from IPs & ports
uint64_t get_flow_key(uint64_t x1, uint64_t x2, uint64_t y1, uint64_t y2);

// create a node (linked list) of flow
Node *create_flow_node(uint64_t key, flow_base_t flow, FILE* stream);

// create a node of payload
Node *create_payload_node(parsed_packet pkt, FILE* stream);

// create new flow from packet info and initialize flow direction
flow_base_t create_flow(parsed_packet pkt, FILE* stream);

// get flow direction by compare src ip of the packet with the flow
Node **get_flow_direction(flow_base_t const *flow, parsed_packet pkt, FILE* stream);

// classify and insert a new packet into hash table
void insert_packet(HashTable table, parsed_packet pkt, FILE* stream);

// insert tcp packet to flow
void insert_tcp_pkt(HashTable table, uint64_t flow_key, parsed_packet pkt, FILE* stream);

// insert udp packet to flow
void insert_udp_pkt(HashTable table, uint64_t flow_key, parsed_packet pkt, FILE* stream);

// filter out wrong-segment payload part 1/2: iteration
void review_table(HashTable table, FILE* stream);

// filter out wrong-segment payload part 2/2: filter in each flow
void filter_packet(Node** head, uint32_t* init_seq, FILE* stream);

// iterate through all ID in hashtable to print
void print_hashtable(HashTable const table, FILE* stream);

// iterate through all flows in list to print
void print_flows(Node const *const head, FILE* stream);

// print all payloads in a flow
void print_flow(flow_base_t flow, FILE* stream);

// print all payloads in a flow direction
void print_flow_direction(Node const *head, bool is_up, FILE* stream);

// print payload from pointer of char with given size (to prevent stopping at '\0')
void print_payload(u_char const *payload, int32_t payload_size, FILE* stream);

// print payload to match the data on wireshark
void print_hex_ascii_line(u_char const *const payload, int32_t len, int32_t offset, FILE* stream);

// Get payloads of a single flow direction and store them as array of strings (double pointer of char)
char** payload_to_strings(Node* flow_direction, FILE* stream);

// Get payloads of a single flow direction and concatenate them into a single string (pointer of char)
char* payload_to_string(Node* flow_direction, FILE* stream);

/* Convert payload string to an array of printable characters, will convert:
 *
 * - Printable characters -> Keep
 *
 * - '\n', '\v', '\f', '\r' -> '\n'
 *
 * - '\t' -> ' '
 */ 
char* convert_payload(char* payload, uint32_t length);

#endif
