#ifndef DISSECTION_H
#define DISSECTION_H

#include "log.h"

#define ETHERNET_HEADER_SIZE 14
#define IPv4 0x0008
#define NONE 0x0000

typedef struct {
  u_char const *header_pointer;
  uint32_t package_size;
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
