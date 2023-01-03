#ifndef HANDLER_H
#define HANDLER_H

#include "hash_table.h"
#include "log.h"
#include "parsers.h"

extern int inserted_packets;

uint64_t get_flow_key(uint64_t x1, uint64_t x2, uint64_t y1, uint64_t y2);

// classify and insert a new packet into hash table
void insert_packet(HashTable table, parsed_packet pkt, FILE *fptr);
void print_hashtable(HashTable const table, FILE *fptr);
void print_flows(Node const *const head, FILE *fptr);

// print all payloads in a flow
void print_flow(flow_base_t flow, FILE *fptr);

// print all payloads in a flow direction
void print_flow_direction(Node const *head, bool is_up, FILE *fptr);
Node *create_flow_node(uint64_t key, flow_base_t flow, FILE *fptr);
Node *create_payload_node(parsed_packet pkt, FILE *fptr);

// create new flow from packet info and initialize flow direction
flow_base_t create_flow(parsed_packet pkt, FILE *fptr);

// get flow direction by compare src ip of the packet with the flow
Node **get_flow_direction(flow_base_t const *flow, parsed_packet pkt,
                          FILE *fptr);

// insert tcp packet to flow
void insert_tcp_pkt(HashTable table, uint64_t flow_key, parsed_packet pkt,
                    FILE *fptr);

// insert udp packet to flow
void insert_udp_pkt(HashTable table, uint64_t flow_key, parsed_packet pkt,
                    FILE *fptr);

void print_payload(u_char const *payload, uint payload_size, FILE *fptr);
void print_hex_ascii_line(u_char const *const payload, int len, int offset,
                          FILE *fptr);

// create new packet node
Node *create_pkt_node(parsed_packet pkt, FILE *stream);
#endif
