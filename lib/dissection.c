#include "dissection.h"
#include "log.h"

// Dessection of ethernet frame, return a frame
package frame_dissector(u_char const *packet,
                        struct pcap_pkthdr const *header, FILE* fout) {

  // Show a warning if the length captured is different
  if (header->len != header->caplen) {
    LOG_DBG(fout, DBG_PARSER, "Warning! Capture size different than package size:\n"
      "header->len = %d bytes\nheader->caplen = %d bytes", header->len, header->caplen
    );
  }

  struct ether_header const *ethernet = (struct ether_header *)(packet);

  return (package){.header_pointer = (u_char *)ethernet,
                   .package_size = header->len,
                   .type = ethernet->ether_type,
                   .is_valid = true};
}

// Dessection of link layer, currently only IPv4, recieves ethernet frame and
// return packet
package link_dissector(package ethernet_packet, FILE* fout) {

  if (ethernet_packet.type == IPv4) {
    u_char const *ip_pointer =
        ethernet_packet.header_pointer + ETHERNET_HEADER_SIZE;
    int ip_packet_size = ethernet_packet.package_size - ETHERNET_HEADER_SIZE;

    return (package){.header_pointer = ip_pointer,
                     .package_size = ip_packet_size,
                     .type = ((struct ip *)ip_pointer)->ip_p,
                     .is_valid = true};
  }

  LOG_DBG(fout, DBG_PARSER, "Not an IPv4\n");;
  return (package){.is_valid = false};
}

// Dessection of network layer, receive packet and return segment
package network_dissector(package packet, FILE* fout) {

  struct ip const *ip = (struct ip *)packet.header_pointer;
  int ip_header_size = ip->ip_hl * 4;
  int ip_total_len = (htons)(ip->ip_len);

  // check size of ip header
  if (ip_header_size < 20) {
    LOG_DBG(fout, DBG_PARSER, "*** Invalid IP header length: %u bytes\n", ip_header_size);;
    goto END;
  }

  // check if TCP type or UDP type
  if (ip->ip_p == IPPROTO_TCP) {

    // get tcp header
    struct tcphdr const *tcp = (struct tcphdr *)(packet.header_pointer + ip_header_size);

    int segment_size = -1;
    if (ip_total_len == 0 || ip_total_len > 1500) {
      // This will handle data length for high-data packet
      segment_size = packet.package_size - ip_header_size;
    } else {
      // This will solve ethernet padding problems low-data packet
      segment_size = ip_total_len - ip_header_size;
    }
    LOG_DBG(fout, DBG_PARSER, "### %u ### %u ### TCP ### %u ### %u ###\n", packet.package_size, ip_total_len, ip_header_size, segment_size);

    return (package){.header_pointer = (u_char *)tcp,
                     .package_size = segment_size,
                     .type = IPPROTO_TCP,
                     .is_valid = true};

  } else if (ip->ip_p == IPPROTO_UDP) {

    // get udp header
    struct udphdr const *udp =
        (struct udphdr *)(packet.header_pointer + ip_header_size);

    int segment_size;
    if (ip_total_len < 28 || ip_total_len > 512) {
      // This will handle data length for high-data packet
      segment_size = packet.package_size - ip_header_size;
    } else {
      // This will solve ethernet padding problems in some low-data packets
      segment_size = ip_total_len - ip_header_size;
    }
    LOG_DBG(fout, DBG_PARSER, "### %u ### %u ### UDP ### %u ### %u ###\n", packet.package_size, ip_total_len, ip_header_size, segment_size);
    return (package){
        .header_pointer = (u_char *)udp,
        .package_size = segment_size,
        .type = IPPROTO_UDP, 
        .is_valid = true,
    };
  }

  END:
    return (package){.is_valid = false};
}

// select the correct transport layer protocol
package transport_demux(package segment, FILE* fout) {

  if (segment.type == IPPROTO_TCP) {
    return tcp_dissector(segment, fout);
  } else if (segment.type == IPPROTO_UDP) {
    return udp_dissector(segment, fout);
  }

  LOG_DBG(fout, DBG_PARSER, "Not TCP or UDP\n");;
  return (package){.is_valid = false};
}

// Dessection of TCP segment, receive segment and return a payload
// NOTE: this function is only for transport_demux function
package tcp_dissector(package segment, FILE* fout) {

  struct tcphdr const *tcp = (struct tcphdr *)segment.header_pointer;
  // fprintf(fout, "Src port: %d\n", ntohs(tcp->th_sport)); 
  // fprintf(fout, "Dst port: %d\n", ntohs(tcp->th_dport)); 

  int tcp_header_size = tcp->th_off * 4;
  // Print sequence number and acknowledgement number and offset 
  // LOG_SCR("seq: %u, ack: %u, offset: %u\n", ntohl(tcp->th_seq), ntohl(tcp->th_ack), tcp->th_off);

  // check size of tcp header
  if (tcp_header_size < 20) {
    LOG_DBG(fout, DBG_PARSER, "***Invalid TCP header length: %u bytes\n", tcp_header_size);;
    return (package){.is_valid = false};
  }

  // get payload size
  int payload_size = segment.package_size - tcp_header_size;
  LOG_DBG(fout, DBG_PARSER, "Pkt_size vs Hdr size: %d,%d\n", segment.package_size, tcp_header_size); ;

  if(payload_size < 0) {
    LOG_DBG(fout, DBG_PARSER, "***Invalid TCP payload length: %u bytes\n", payload_size);;
    return (package){.is_valid = false};
  }

  u_char const *payload = (u_char *)(segment.header_pointer + tcp_header_size);

  return (package){.header_pointer = payload,
                   .package_size = payload_size,
                   .type = NONE,
                   .is_valid = true};
}

// Dessection of UDP segment, receive segment and return a payload
// NOTE: this function is only for transport_demux function
package udp_dissector(package segment, FILE* fout) {

  // const struct udphdr *udp = (struct udphdr *)segment.header_pointer;

  // // print source and destination port
  // fprintf(fout, "Src port: %d\n", ntohs(udp->uh_sport));
  // fprintf(fout, "Dst port: %d\n", ntohs(udp->uh_dport));

  int udp_header_size = 8;

  // get payload
  u_char const *payload = (u_char *)(segment.header_pointer + udp_header_size);
  
  // get payload size using udp header
  int payload_size = segment.package_size - udp_header_size; 

  // print length of payload + checksum
  return (package){.header_pointer = payload,
                   .package_size = payload_size,
                   .type = NONE,
                   .is_valid = true};
}

