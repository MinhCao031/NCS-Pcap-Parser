#include <pcap.h>
#include "lib/handler.h"

void get_packets(pcap_t *handler, FILE* fout_parser, FILE* fout_seq_filter, FILE* fout_list_flow);
uint32_t sttstc[27];

int main(void) {
  // error buffer
  char errbuff[PCAP_ERRBUF_SIZE];

  // open file and create pcap handler
  pcap_t *const handler = pcap_open_offline(PCAP_FILE, errbuff);
  if (handler == NULL) {
    printf("Error opening file: %s\n", errbuff);
    exit(EXIT_FAILURE);
  }

  get_packets(handler, OUTPUT_1, OUTPUT_2, OUTPUT_3);
  pcap_close(handler);

  if (OUTPUT_1) fclose(OUTPUT_1);
  if (OUTPUT_2) fclose(OUTPUT_2);
  if (OUTPUT_3) fclose(OUTPUT_3);
  return 0;
}

void get_packets(pcap_t *handler, FILE* fout_parser, FILE* fout_seq_filter, FILE* fout_list_flow) {

  // The header that pcap gives us
  struct pcap_pkthdr *header_pcap;

  // The actual packet
  u_char const* full_packet;

  struct timespec pkt_start, pkt_end;
  uint64_t process_time = 0;
  uint64_t process_time_total = 0;
  uint32_t packet_count = 0;

  // create hash table
  HashTable table = create_hash_table(HASH_TABLE_SIZE);

  while (pcap_next_ex(handler, &header_pcap, &full_packet) >= 0) {

    // Show the packet number & timestamp
    GET_FULL_TIMESTAMP;
    packet_count++;
    // printf("#%d\n", ++packet_count);

    LOG_DBG(fout_parser, DBG_PARSER,
      "Packet # %i\nTime in sec & microsec: %lu.%7lu\nFull timestamp = %s\n",
      packet_count, (header_pcap->ts).tv_sec, (header_pcap->ts).tv_usec, full_timestamp
    );

    clock_gettime(CLOCK_REALTIME, &pkt_start);

    int8_t progress_pkt = 1;
    // Dissection Step 1 of 4----------------------------------------------------------------------
    package frame = frame_dissector(full_packet, header_pcap, fout_parser);
    if (frame.is_valid == false) {
      LOG_DBG(fout_parser, DBG_PARSER, "ERROR: Frame is not valid!\n");
      clock_gettime(CLOCK_REALTIME, &pkt_end);
      goto END;
    }

    progress_pkt += 1;
    // Dissection Step 2 of 4----------------------------------------------------------------------
    package packet = link_dissector(frame, fout_parser);
    if (packet.is_valid == false) {
      LOG_DBG(fout_parser, DBG_PARSER, "ERROR: Packet is not valid!\n");
      clock_gettime(CLOCK_REALTIME, &pkt_end);
      goto END;
    }

    progress_pkt += 1;
    // Dissection Step 3 of 4----------------------------------------------------------------------
    package segment = network_dissector(packet, fout_parser);
    if (segment.is_valid == false) {
      LOG_DBG(fout_parser, DBG_PARSER, "ERROR: Segment is not valid!\n");
      clock_gettime(CLOCK_REALTIME, &pkt_end);
      goto END;
    }

    progress_pkt += 1;
    // Dissection Step 4 of 4----------------------------------------------------------------------
    package payload = transport_demux(segment, fout_parser);
    if (payload.is_valid == false) {
      LOG_DBG(fout_parser, DBG_PARSER, "ERROR: Payload is not valid!\n");
      clock_gettime(CLOCK_REALTIME, &pkt_end);
      goto END;
    }

    progress_pkt += 1;
    // Store packets in the hash table
    parsed_packet pkt = pkt_parser(packet, segment, payload);

    insert_packet(table, pkt, fout_parser);
    clock_gettime(CLOCK_REALTIME, &pkt_end);

    // if (pkt.payload.data_len > 0) printf(
    //   "Tracking #%-3u SEQ = %10u => %10u, ACK = %10u\n", packet_count,
    //   pkt.tcp.seq, pkt.tcp.seq + pkt.payload.data_len, pkt.tcp.ack_seq
    // );

    progress_pkt += 1;
    PROCESS_PACKET_TIME(50000);
    LOG_DBG(fout_parser, DBG_PARSER,
      "----------------------------------------"
      "-----------Successfully---------------\n");
    if (packet_count > LIMIT_PACKET) break;
    continue;

    END: {
      PROCESS_PACKET_TIME(50000);
      LOG_DBG(fout_parser, DBG_PARSER,
        "----------------------------------------"
        "-----------PacketFailed---------------\n");
      if (packet_count > LIMIT_PACKET) break;
    }
  }

  STATISTIC_PACKET_TIME;

  // Print HashTable
  print_hashtable(table, fout_list_flow);

  // Test a random flow
  // printf("\nTest 01: Get a random flow\n");

  // flow_base_t* flow_test = search_flow(table, 6813568831684183325, stdout);
  // if (flow_test) {
  //   print_flow(*flow_test, stdout);
  //   printf("\nTest 02: Get payloads in flow\n");
  //   // char* long_payload = payload_to_string(flow_test->head_flow, flow_test->total_payload);
  //   // printf("All payload in this flow:\n%s\n\n<END OF FLOW>\n", long_payload);
  // } else printf("Flow not found.\n");

  LOG_DBG(fout_list_flow, DBG_FLOW,
    "Number of packets: %u\nNumber of flows: %u\n"
    "Number of inserted packets: %u\nNumber of filtered packets: %u\n",
    packet_count, count_flows(table), inserted_packets, filtered_packets
  );

  printf("\nTest 03: Freeing...\n");
  // free_hash_table(table);
}
