#include "lib/dissect_smtp.h"
#include "lib/handler.h"
#include "lib/dissect_imf.h"

void flow_browser(flow_base_t  * flow) {

  if (flow == NULL) {
    printf("ERROR: flow is null\n");
    return;
  }
  struct smtp_session_state session_state = {.smtp_state = SMTP_STATE_START,
                                             .auth_state = SMTP_AUTH_STATE_NONE,
                                             .msg_last = true};

  Parsed_smtp *smtp_info = g_malloc(sizeof(Parsed_smtp));
  smtp_info->num_fragments = 0;
  smtp_info->fragments = NULL;
  smtp_info->defragment_size = 0;

  Node const *temp = flow->head_flow;

  while (temp != NULL) {

    smtp_decoder(((parsed_payload *)temp->value)->data,
                 ((parsed_payload *)temp->value)->data_len, &session_state,
                 ((parsed_payload *)temp->value)->is_up,
                 ((parsed_payload *)temp->value)->index, smtp_info);

    temp = temp->next;
  }

  u_char *defragment = NULL;
  // print fragments
  if (smtp_info->num_fragments > 0) {
     printf("User: %s\n", smtp_info->username);
     printf("Password: %s\n", smtp_info->password);
     printf("Num Fragments: %d\n", smtp_info->num_fragments);
     printf("Content length: %ld\n", smtp_info->defragment_size);
     printf("Fragments:\n");

     // print all fragments in smtp_info->fragments, note that this is GSList
     for (GSList *temp = smtp_info->fragments; temp != NULL; temp =
     temp->next) {
       printf("%s\n", (char *)temp->data);
     }

    // merge all fragments in smtp_info->fragments to one string
    defragment = g_malloc(smtp_info->defragment_size + 1);
    size_t offset = 0;
    for (GSList *temp = smtp_info->fragments; temp != NULL; temp = temp->next) {
      // memcpy(defragment + offset, temp->data, strlen(temp->data));
      // using strcpy instead of memcpy to avoid copying \0 characters
      strcpy((char *)defragment + offset, (char *)temp->data);
      offset += strlen(temp->data);
    }
    defragment[smtp_info->defragment_size] = '\0';

    // print defragment
    // printf("%s\n", defragment);
  }

  // dissect_imf(defragment, smtp_info->defragment_size);
}

void get_packets(pcap_t *handler, FILE *fout_parser, FILE *fout_seq_filter,
                 FILE *fout_list_flow);
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

  if (OUTPUT_1)
    fclose(OUTPUT_1);
  if (OUTPUT_2)
    fclose(OUTPUT_2);
  if (OUTPUT_3)
    fclose(OUTPUT_3);
  return 0;
}

void get_packets(pcap_t *handler, FILE *fout_parser, FILE *fout_seq_filter,
                 FILE *fout_list_flow) {

  // The header that pcap gives us
  struct pcap_pkthdr *header_pcap;

  // The actual packet
  u_char const *full_packet;

  // create hash table
  HashTable table = create_hash_table(HASH_TABLE_SIZE);

  while (pcap_next_ex(handler, &header_pcap, &full_packet) >= 0) {

    captured_packets++;
    // printf("#%d\n", ++captured_packets);

    int8_t progress_pkt = 1;
    // Dissection Step 1 of
    // 4----------------------------------------------------------------------
    package frame = frame_dissector(full_packet, header_pcap, fout_parser);
    if (frame.is_valid == false) {
      LOG_DBG(fout_parser, DBG_PARSER, "ERROR: Frame is not valid!\n");
      goto END;
    }

    progress_pkt += 1;
    // Dissection Step 2 of
    // 4----------------------------------------------------------------------
    package packet = link_dissector(frame, fout_parser);
    if (packet.is_valid == false) {
      LOG_DBG(fout_parser, DBG_PARSER, "ERROR: Packet is not valid!\n");
      goto END;
    }

    progress_pkt += 1;
    // Dissection Step 3 of
    // 4----------------------------------------------------------------------
    package segment = network_dissector(packet, fout_parser);
    if (segment.is_valid == false) {
      LOG_DBG(fout_parser, DBG_PARSER, "ERROR: Segment is not valid!\n");
      goto END;
    }

    progress_pkt += 1;
    // Dissection Step 4 of
    // 4----------------------------------------------------------------------
    package payload = transport_demux(segment, fout_parser);
    if (payload.is_valid == false) {
      LOG_DBG(fout_parser, DBG_PARSER, "ERROR: Payload is not valid!\n");
      goto END;
    }

    progress_pkt += 1;
    // Store packets in the hash table
    parsed_packet pkt = pkt_parser(packet, segment, payload);

    insert_packet(table, pkt, fout_parser);

    progress_pkt += 1;
    LOG_DBG(fout_parser, DBG_PARSER,
            "----------------------------------------"
            "-----------Successfully---------------\n");
    if (captured_packets > LIMIT_PACKET)
      break;
    continue;

  END : {
    LOG_DBG(fout_parser, DBG_PARSER,
            "----------------------------------------"
            "-----------PacketFailed---------------\n");
    if (captured_packets > LIMIT_PACKET)
      break;
  }
  }

  print_hashtable(table, fout_list_flow);

  flow_base_t *flow_test = search_flow(table, 5676399932842470375, stdout);
  // flow_browser(flow_test);

  printf("\nFreeing...\n");
  free_hash_table(table);
}
