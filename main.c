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

  // create hash table
  HashTable table = create_hash_table(HASH_TABLE_SIZE);

  while (pcap_next_ex(handler, &header_pcap, &full_packet) >= 0) {

    // Show the packet number & timestamp
    GET_FULL_TIMESTAMP;
    captured_packets++;
    // printf("#%d\n", ++captured_packets);
    // if (captured_packets > 35) break;

    LOG_DBG(fout_parser, DBG_PARSER,
      "Packet # %i\nTime in sec & microsec: %lu.%7lu\nFull timestamp = %s\n",
      captured_packets, (header_pcap->ts).tv_sec, (header_pcap->ts).tv_usec, full_timestamp
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

    // printf(
    //   "Tracking #%-3u SEQ = %10u => %10u, ACK = %10u\n", captured_packets,
    //   pkt.tcp.seq, pkt.tcp.seq + pkt.payload.data_len, pkt.tcp.ack_seq
    // );

    progress_pkt += 1;
    PROCESS_PACKET_TIME(50000);
    LOG_DBG(fout_parser, DBG_PARSER,
      "----------------------------------------"
      "-----------Successfully---------------\n");
    if (captured_packets > LIMIT_PACKET) break;
    continue;

    END: {
      PROCESS_PACKET_TIME(50000);
      LOG_DBG(fout_parser, DBG_PARSER,
        "----------------------------------------"
        "-----------PacketFailed---------------\n");
      if (captured_packets > LIMIT_PACKET) break;
    }
  }

  STATISTIC_PACKET_TIME;

  // Print HashTable
  print_hashtable(table, fout_list_flow);

  // Test a random flow
  printf("\nTest 01: Get a random flow\n");

  flow_base_t* flow_test = search_flow(table, 6359988029046827285, stdout);
  if (flow_test) {
    print_flow(*flow_test, stdout);
    printf("\nTest 02: Get payloads in flow\n");
    char* long_payload = payload_to_string(flow_test->head_flow, flow_test->total_payload);
    printf("All payload in this flow:\n%s\n\n<END OF FLOW>\n", long_payload);
  } else printf("Flow not found.\n");

  LOG_DBG(fout_list_flow, DBG_FLOW,
    "Number of packets: %u\nNumber of flows: %u\n"
    "Number of inserted packets: %u\nNumber of filtered packets: %u\n",
    captured_packets, count_flows(table), inserted_packets, filtered_packets
  );

  printf("\nTest 03: Freeing...\n");
  free_hash_table(table);
}


/*


Tracking #4   SEQ = 1436401060 => 1436401259, ACK = 2834331614 Tracking #4   SEQ = 1436401060 => 1436401259, ACK = 2834331614

Tracking #5   SEQ = 2834331614 => 2834333074, ACK = 1436401259

Tracking #6   SEQ = 2834333074 => 2834334534, ACK = 1436401259

Tracking #8   SEQ = 2834334534 => 2834335594, ACK = 1436401259

Tracking #9   SEQ = 1436401259 => 1436401385, ACK = 2834335594 Tracking #9   SEQ = 1436401259 => 1436401385, ACK = 2834335594

Tracking #10  SEQ = 1436401385 => 1436401562, ACK = 2834335594 Tracking #10  SEQ = 1436401385 => 1436401562, ACK = 2834335594

Tracking #11  SEQ = 1436401562 => 1436401847, ACK = 2834335594 Tracking #11  SEQ = 1436401562 => 1436401847, ACK = 2834335594

Tracking #12  SEQ = 2834335594 => 2834335852, ACK = 1436401385

Tracking #14  SEQ = 2834335852 => 2834335918, ACK = 1436401847

Tracking #16  SEQ = 1436401847 => 1436401885, ACK = 2834335918 Tracking #16  SEQ = 1436401847 => 1436401885, ACK = 2834335918

Tracking #17  SEQ = 2834335918 => 2834337378, ACK = 1436401847

Tracking #18  SEQ = 2834337378 => 2834338235, ACK = 1436401847

Tracking #21  SEQ = 1436401885 => 1436401931, ACK = 2834338235 Tracking #21  SEQ = 1436401885 => 1436401931, ACK = 2834338235

Tracking #23  SEQ = 2834338235 => 2834338293, ACK = 1436401885

Tracking #24  SEQ = 2834338293 => 2834338324, ACK = 1436401885

Tracking #27  SEQ = 2834338235 => 2834338293, ACK = 1436401885

Tracking #34  SEQ = 2834338235 => 2834338293, ACK = 1436401885

*/
