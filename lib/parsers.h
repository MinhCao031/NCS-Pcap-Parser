#ifndef PARSER_H
#define PARSER_H

#include "dissection.h"

extern uint32_t captured_packets;
extern uint32_t inserted_packets;
extern uint32_t filtered_packets;

typedef struct {
  uint32_t index; // index of packet in wireshark file
  uint16_t data_len;
  uint8_t is_up;
  uint8_t is_truncated;
  u_char const *data;
} parsed_payload;

typedef struct {

  // currently only used for IPv4
  // struct in_addr src_ip;
  // struct in_addr dst_ip;

  // protocol
  // uint16_t protocol;

  struct ip ip_header;

  union {
    struct tcphdr tcp;
    struct udphdr udp;
  };

  parsed_payload payload;

} parsed_packet;

parsed_packet pkt_parser(package packet, package segment, package payload);

void tcp_parser(parsed_packet *pkt, package segment, package payload);
void udp_parser(parsed_packet *pkt, package segment, package payload);

#endif
