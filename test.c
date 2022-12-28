#include "lib/handler.h"
#include "lib/log.h"

void get_packets(pcap_t *handler, FILE *stream_parser, FILE *stream_flow,
                 FILE *stream_err);

int main(void) {
  // error buffer
  char errbuff[PCAP_ERRBUF_SIZE];

  // open file and create pcap handler
  pcap_t *const handler = pcap_open_offline(PCAP_FILE, errbuff);
  if (handler == NULL) {
    LOG_DBG(OUTPUT_E, DBG_ERROR, "Error opening file: %s\n", errbuff);
    exit(EXIT_FAILURE);
  }

  get_packets(handler, OUTPUT_1, OUTPUT_2, OUTPUT_0);
  // get_packets(handler, OUTPUT_1, OUTPUT_0, OUTPUT_0);
  pcap_close(handler);
  fclose(OUTPUT_1);
  fclose(OUTPUT_2);
  fclose(OUTPUT_E);
  return 0;
}

void get_packets(pcap_t *handler, FILE *stream_parser, FILE *stream_flow,
                 FILE *stream_err) {

  // The header that pcap gives us
  struct pcap_pkthdr *header;

  // The actual packet
  u_char const *full_packet;

  int packetCount = 0;

  // create hash table
  HashTable table = create_hash_table(HASH_TABLE_SIZE);

  while (pcap_next_ex(handler, &header, &full_packet) >= 0) {

    // Show the packet number
    LOG_DBG(stream_parser, DBG_PARSER, "Packet # %i\n", ++packetCount);

    //--------------------------------------------------------------------------
    package frame = frame_dissector(full_packet, header, stream_parser);
    if (frame.is_valid == false) {
      LOG_DBG(stream_parser, DBG_PARSER, "ERROR: Frame is not valid!\n");
      goto END;
    }

    //--------------------------------------------------------------------------
    package packet = link_dissector(frame, stream_parser);
    if (packet.is_valid == false) {
      LOG_DBG(stream_parser, DBG_PARSER, "ERROR: Packet is not valid!\n");
      goto END;
    }

    //--------------------------------------------------------------------------
    package segment = network_dissector(packet, stream_parser);
    if (segment.is_valid == false) {
      LOG_DBG(stream_parser, DBG_PARSER, "ERROR: Segment is not valid!\n");
      goto END;
    }

    //--------------------------------------------------------------------------
    package payload = transport_demux(segment, stream_parser);
    if (payload.is_valid == false) {
      LOG_DBG(stream_parser, DBG_PARSER, "ERROR: Payload is not valid!\n");
      goto END;
    }

    // insert to hash table
    parsed_packet pkt = pkt_parser(frame, packet, segment, payload);
    insert_packet(table, pkt, stream_parser);
    LOG_DBG(stream_parser, DBG_PARSER,
            "------------------------------------------------Successfully------"
            "------\n");
    if (packetCount > LIMIT_PACKET)
      break;
    continue;

  END : {
    LOG_DBG(stream_parser, DBG_PARSER,
            "------------------------------------------------PacketFailed------"
            "------\n");
    if (packetCount > LIMIT_PACKET)
      break;
  }
  }

  print_hashtable(table, stream_flow);
  // LOG_DBG(stream_flow, DBG_FLOW, "data length: %d\n",
  // pop_head_payload(&search_flow(table,
  // 3316805598312908751)->flow_up).data_len); print_flow(*search_flow(table,
  // 94129317375700));
  LOG_DBG(stream_flow, DBG_FLOW, "number of flows: %d\n", count_flows(table));
  LOG_DBG(stream_flow, DBG_FLOW, "Number of packets: %d ~ %d\n",
          count_packets(table), inserted_packets++);

  free_hash_table(table);
}
