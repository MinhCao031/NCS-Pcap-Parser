#include "parsers.h"

guint32 captured_packets = 0;
guint32 inserted_packets = 0;
guint32 filtered_packets = 0;

parsed_packet pkt_parser(const package packet, const package segment,
                         const package payload) {

  parsed_packet pkt;
  const struct ip *ip_header = (struct ip *)packet.header_pointer;
  pkt.ip_header = (*ip_header);

  if (segment.type == IPPROTO_TCP) {
    tcp_parser(&pkt, segment, payload);
  } else if (segment.type == IPPROTO_UDP) {
    udp_parser(&pkt, segment, payload);
  }

  return pkt;
}

void tcp_parser(parsed_packet *pkt, package segment, package payload) {

  const struct tcphdr *tcp_header = (struct tcphdr *)segment.header_pointer;

  (*pkt).ip_header.ip_p = IPPROTO_TCP;
  (*pkt).tcp.source = ntohs(tcp_header->source);
  (*pkt).tcp.dest = ntohs(tcp_header->dest);
  (*pkt).tcp.seq = ntohl(tcp_header->seq);
  (*pkt).tcp.ack_seq = ntohl(tcp_header->ack_seq);
  (*pkt).tcp.th_flags = tcp_header->th_flags;
  (*pkt).payload.data = payload.header_pointer;
  (*pkt).payload.data_len = payload.package_size;

}

void udp_parser(parsed_packet *pkt, package segment, package payload) {

  const struct udphdr *udp_header = (struct udphdr *)segment.header_pointer;

  (*pkt).ip_header.ip_p = IPPROTO_UDP;
  (*pkt).udp.source = ntohs(udp_header->source);
  (*pkt).udp.dest = ntohs(udp_header->dest);
  (*pkt).payload.data = payload.header_pointer;
  (*pkt).payload.data_len = payload.package_size;

}
