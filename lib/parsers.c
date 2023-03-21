#include "parsers.h"

parsed_packet pkt_parser(const package packet, const package segment,
                         const package payload) {

  parsed_packet pkt;
  const struct ip *ip_header = (struct ip *)packet.header_pointer;
  pkt.ip_header = (*ip_header);

  // // print IP addresses */
  // pkt.src_ip = ip_header->ip_src;
  // pkt.dst_ip = ip_header->ip_dst;
  // LOG_SCR("Source IP: %s\n", inet_ntoa((*pkt).src_ip)); */
  // LOG_SCR("Destination IP: %s\n", inet_ntoa((*pkt).dst_ip)); */

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

  // printf("seq %u & %u\n", (*pkt).tcp.ack_seq, ntohl(tcp_header->ack_seq));


  // LOG_SCR("Protocol: TCP\n"); */
  // LOG_SCR("Source port: %d\n", (*pkt).src_port); */
  // LOG_SCR("Destination port: %d\n", (*pkt).dst_port); */
  // LOG_SCR("Sequence number: %ld\n", (*pkt).seq); */
  // LOG_SCR("Payload size: %d\n", (*pkt).payload.data_len); */
}

void udp_parser(parsed_packet *pkt, package segment, package payload) {

  const struct udphdr *udp_header = (struct udphdr *)segment.header_pointer;

  (*pkt).ip_header.ip_p = IPPROTO_UDP;
  (*pkt).udp.source = ntohs(udp_header->source);
  (*pkt).udp.dest = ntohs(udp_header->dest);
  (*pkt).payload.data = payload.header_pointer;
  (*pkt).payload.data_len = payload.package_size;

  // LOG_SCR("Protocol: UDP\n"); */
  // LOG_SCR("Source port: %d\n", (*pkt).src_port); */
  // LOG_SCR("Destination port: %d\n", (*pkt).dst_port); */
  // LOG_SCR("Payload size: %d\n", (*pkt).payload.data_len); */
}
