#include "parsers.h"
#include "dissection.h"

#define MAC_SIZE 6

parsed_packet pkt_parser(const package frame, const package packet,
                         const package segment, const package payload) {

  parsed_packet pkt;

  pkt.pkt_size = frame.package_size ;

  const struct ether_header *ethernet_header =
      (struct ether_header *)frame.header_pointer;
  for (int i = 0; i < MAC_SIZE; i++) {
    pkt.ethernet.ether_dhost[i] = (ethernet_header->ether_dhost)[i];
    pkt.ethernet.ether_shost[i] = (ethernet_header->ether_shost)[i];
  }
  pkt.ethernet.ether_type = ethernet_header->ether_type;

  /** printf("Source MAC: %s\n", */
  /**        ether_ntoa((struct ether_addr *)pkt.ethernet.ether_shost)); */
  /** printf("Destination MAC: %s\n", */
  /**        ether_ntoa((struct ether_addr *)pkt.ethernet.ether_dhost)); */

  const struct ip *ip_header = (struct ip *)packet.header_pointer;

  pkt.ip_header.ip_src = ip_header->ip_src;
  pkt.ip_header.ip_dst = ip_header->ip_dst;
  pkt.ip_header.ip_ttl = ip_header->ip_ttl;
  pkt.ip_header.ip_tos = ip_header->ip_tos;

  /** // print IP addresses */
  /** printf("Source IP: %s\n", inet_ntoa(pkt.ip_header.ip_src)); */
  /** printf("Destination IP: %s\n", inet_ntoa(pkt.ip_header.ip_dst)); */
  /** printf("Time to live: %d\n", pkt.ip_header.ip_ttl); */

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
  (*pkt).tcp.th_win = tcp_header->th_win;

  /** printf("Protocol: TCP\n"); */
  /** printf("Source port: %d\n", (*pkt).tcp.source); */
  /** printf("Destination port: %d\n", (*pkt).tcp.dest); */
  /** printf("Sequence number: %d\n", (*pkt).tcp.seq); */
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
  /** printf("Source port: %d\n", (*pkt).udp.source); */
  /** printf("Destination port: %d\n", (*pkt).udp.dest); */
  /** printf("Payload size: %d\n", (*pkt).payload.data_len); */
}
