#ifndef DISSECTION_H
#define DISSECTION_H

#include <ctype.h>
#include <pcap.h>
#include <stdbool.h>

#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#define ETHERNET_HEADER_SIZE 14
#define IPv4 0x0008
#define NONE 0x0000

typedef struct {
  u_char const *header_pointer;
  uint package_size;
  uint16_t type;
  bool is_valid;
} package;

package frame_dissector(u_char const *packet, struct pcap_pkthdr const *header, FILE* fptr);
package link_dissector(package frame, FILE* fptr);
package network_dissector(package packet, FILE* fptr);

// select the correct transport layer protocol
package transport_demux(package segment, FILE* fptr);
package tcp_dissector(package segment, FILE* fptr);
package udp_dissector(package segment, FILE* fptr);


#endif
