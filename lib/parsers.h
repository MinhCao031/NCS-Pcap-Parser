#ifndef PARSER_H
#define PARSER_H

#include "dissection.h"

extern guint32 captured_packets;
extern guint32 inserted_packets;
extern guint32 filtered_packets;

typedef struct {
  guint32 index; // index frame of packet in wireshark file
  guint16 data_len;
  guint8 is_up;
  guint8 is_truncated;
  u_char const *data;
} parsed_payload;

#define PP_PTR(payload) ((parsed_payload *)(payload))
#define PP_IN_NODE(node) PP_PTR((node)->value)
#define PP_FRAME(node) PP(node)->index;
#define PP_DTLEN(node) PP(node)->data_len;
#define PP_IS_UP(node) PP(node)->is_up;
#define PP_TRUNC(node) PP(node)->trunc;
#define PP_CDATA(node) PP(node)->data;

typedef struct {

  // currently only used for IPv4
  // struct in_addr src_ip;
  // struct in_addr dst_ip;

  // protocol
  // guint16 protocol;

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
