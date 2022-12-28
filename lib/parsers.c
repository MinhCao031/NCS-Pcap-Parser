#include "parsers.h"
#include "dissection.h"

parsed_packet pkt_parser(const package packet, const package segment,
                         const package payload) {

  parsed_packet pkt;

  const struct ip *ip_header = (struct ip *)packet.header_pointer;

  pkt.ip_header = (*ip_header);
  // pkt.src_ip = ip_header->ip_src;
  // pkt.dst_ip = ip_header->ip_dst;

  /** // print IP addresses */
  /** printf("Source IP: %s\n", inet_ntoa((*pkt).src_ip)); */
  /** printf("Destination IP: %s\n", inet_ntoa((*pkt).dst_ip)); */

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
  (*pkt).tcp.ack = ntohl(tcp_header->ack);
  (*pkt).tcp.th_flags = tcp_header->th_flags;
  (*pkt).payload.data = payload.header_pointer;
  (*pkt).payload.data_len = payload.package_size;

  /** printf("Protocol: TCP\n"); */
  /** printf("Source port: %d\n", (*pkt).src_port); */
  /** printf("Destination port: %d\n", (*pkt).dst_port); */
  /** printf("Sequence number: %ld\n", (*pkt).seq); */
  /** printf("Payload size: %d\n", (*pkt).payload.data_len); */
}

void udp_parser(parsed_packet *pkt, package segment, package payload) {

  const struct udphdr *udp_header = (struct udphdr *)segment.header_pointer;

  (*pkt).ip_header.ip_p = IPPROTO_UDP;
  (*pkt).udp.source = ntohs(udp_header->source);
  (*pkt).udp.dest = ntohs(udp_header->dest);
  (*pkt).payload.data = payload.header_pointer;
  (*pkt).payload.data_len = payload.package_size;

  /** printf("Protocol: UDP\n"); */
  /** printf("Source port: %d\n", (*pkt).src_port); */
  /** printf("Destination port: %d\n", (*pkt).dst_port); */
  /** printf("Payload size: %d\n", (*pkt).payload.data_len); */
}
