#ifndef HANDLER_H
#define HANDLER_H

#include "hash_table.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

// arguments parser, return 1+ if any debug type is active
gint8 parse_arg(int argc, char *argv[]);

// get key from IPs & ports
guint64 get_flow_key(guint64 x1, guint64 x2, guint64 y1, guint64 y2);

// create a node (linked list) of flow
Node *create_flow_node(guint64 key, flow_base_t flow);

// create a node of payload
Node *create_payload_node(parsed_packet pkt, bool is_pkt_up, guint32 skip_byte);

// create new flow from packet info and initialize flow direction
flow_base_t create_flow(parsed_packet pkt, FILE* stream);

// Get direction of a packet by compare src ip of the packet with the flow
bool is_packet_up(flow_base_t const *flow, parsed_packet pkt);

// classify and insert a new packet into hash table
void insert_packet(HashTable table, parsed_packet pkt, FILE* stream);

// insert tcp packet to flow
void insert_tcp_pkt(HashTable table, parsed_packet pkt, FILE* stream);

// insert udp packet to flow
void insert_udp_pkt(HashTable table, parsed_packet pkt, FILE* stream);

// iterate through all ID in hashtable to print
void print_hashtable(HashTable const table, FILE* stream);

// iterate through all flows in list to print
void print_flows(Node const *const head, FILE* stream);

// print all payloads in a flow
void print_flow(flow_base_t flow, FILE* stream);

// print payload from pointer of char with given size (to prevent stopping at '\0')
void print_payload(u_char const *payload, gint32 payload_size, FILE* stream);

// print payload to match the data on wireshark
void print_hex_ascii_line(u_char const *const payload, gint32 len, gint32 offset, FILE* stream);

// Get payloads of a single flow direction and concatenate them into a single string (pointer of char)
char* payload_to_string(Node* flow_direction, guint32 len_need);

/* Convert payload string to an array of printable characters, will convert:
 *
 * - Printable characters   -> Keep
 * - '\t', '\n', '\r'       -> Keep
 * - '\v', '\f'             -> '\n'
 * - Others                 -> '.'
 */
char* convert_payload(char* payload, guint32 length);

#endif
