#include "lib/handler.h"
#include "lib/log.h"
#include <time.h>
#include <sys/time.h>
#include <pcap.h>

void get_packets(pcap_t *handler, FILE* fout_parser, FILE* fout_seq_filter, FILE* fout_list_flow);
uint32_t sttstc[27];

int main(void) {
  // error buffer
  char errbuff[PCAP_ERRBUF_SIZE];

  // open file and create pcap handler
  pcap_t *const handler = pcap_open_offline(PCAP_FILE, errbuff);
  if (handler == NULL) {
    LOG_DBG(OUTPUT_0, DBG_ERROR, "Error opening file: %s\n", errbuff);
    printf("Error opening file: %s\n", errbuff);
    exit(EXIT_FAILURE);
  }

  get_packets(handler, OUTPUT_1, OUTPUT_2, OUTPUT_3);
  
  pcap_close(handler);
  fclose(OUTPUT_1);
  fclose(OUTPUT_2);
  fclose(OUTPUT_3);
  fclose(OUTPUT_4);
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
    // printf("%d ", packet_count++);

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
    progress_pkt += 1;
    process_time = (pkt_end.tv_sec - pkt_start.tv_sec) * SEC2NANO + pkt_end.tv_nsec - pkt_start.tv_nsec;
    process_time_total += process_time;
    if (process_time < 1001) sttstc[process_time/100 - 3] += 1;
    else if (process_time < 10001) sttstc[6 + (process_time + 999)/1000] += 1;
    else if (process_time < 100001) sttstc[15 + (process_time + 9999)/10000] += 1;
    else sttstc[26] += 1;

    LOG_DBG(fout_parser, 1 && (process_time > 50000), "Packet%8u:%7lu nanosec stoped at step %d of 6\n", packet_count, process_time, progress_pkt);
    LOG_DBG(fout_parser, DBG_PARSER,
      "----------------------------------------"
      "-----------Successfully---------------\n");
    // LOG_DBG(OUTPUT_4, 0, "***After packet %u: %u packets.\n", packet_count, count_packets(table));   
    if (packet_count > LIMIT_PACKET) break;
    continue;

    END: {
      process_time = (pkt_end.tv_sec - pkt_start.tv_sec) * SEC2NANO + pkt_end.tv_nsec - pkt_start.tv_nsec;
      process_time_total += process_time;
      if (process_time < 1001) sttstc[process_time/100 - 3] += 1;
      else if (process_time < 10001) sttstc[6 + (process_time + 999)/1000] += 1;
      else if (process_time < 100001) sttstc[15 + (process_time + 9999)/10000] += 1;
      else sttstc[26] += 1;
      LOG_DBG(fout_parser, 1 && (process_time > 50000), "Packet%8u:%7lu nanosec stoped at step %d of 6\n", packet_count, process_time, progress_pkt);
      LOG_DBG(fout_parser, DBG_PARSER,
        "----------------------------------------"
        "---------PacketFailed-----------------\n");
      if (packet_count > LIMIT_PACKET) break;
    }
  }

  LOG_DBG(fout_parser, 1, "Packet time total: %lu\n", process_time_total);
  LOG_DBG(fout_parser, 1, "Average time process: %lf\n", 1.0*process_time_total/packet_count);

  for (uint8_t i = 0; i < 8; i++) {
    LOG_DBG(fout_parser, 1,"= %-6u nanosec: %5u time(s)\n", (i+3)*100, sttstc[i]);
  }
  for (uint8_t i = 8; i < 17; i++) {
    LOG_DBG(fout_parser, 1,"<=%-6u nanosec: %5u time(s)\n", (i-6)*1000, sttstc[i]);
  }
  for (uint8_t i = 17; i < 26; i++) {
    LOG_DBG(fout_parser, 1,"<=%-6u nanosec: %5u time(s)\n", (i-15)*10000, sttstc[i]);
  }
  LOG_DBG(fout_parser, 1,"> 100000 nanosec: %5u time(s)\n", sttstc[26]);

  clock_gettime(CLOCK_REALTIME, &pkt_start);
  review_table(table, fout_seq_filter);
  clock_gettime(CLOCK_REALTIME, &pkt_end);
  process_time = (pkt_end.tv_sec - pkt_start.tv_sec) * SEC2NANO + pkt_end.tv_nsec - pkt_start.tv_nsec;

  LOG_DBG(fout_parser, 1, "After-processing:%12lu nanosec\n", process_time);
  LOG_DBG(fout_parser, 1, "Average time process: %lf\n", 1.0*process_time/inserted_packets);

  print_hashtable(table, fout_list_flow);

  LOG_DBG(fout_list_flow, 1 + DBG_FLOW, "Number of flows: %d\n", count_flows(table));
  LOG_DBG(fout_list_flow, 1 + DBG_FLOW, "Number of packets: %d ~ %d\n", count_packets(table), inserted_packets);
  LOG_DBG(fout_list_flow, 1 + DBG_FLOW, "Number of filtered packets: %d\n", filtered_packets);

  LOG_DBG(fout_parser, 1, "Program run successfully");
  free_hash_table(table);
}
