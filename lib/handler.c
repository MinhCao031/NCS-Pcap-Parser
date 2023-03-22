#include "handler.h"

uint32_t inserted_packets = 0;
uint32_t filtered_packets = 0;
uint32_t dbg_count = 0;

uint64_t get_flow_key(uint64_t ip1, uint64_t ip2, uint64_t p1, uint64_t p2) {
  uint64_t half64 = 2147483648;
  uint64_t ans = (ip1 + ip2) * half64 + (p1*p1 - p1*p2 + p2*p2);
  return ans;
}

// classify and insert a new packet into hash table
void insert_packet(HashTable table, parsed_packet pkt, FILE* stream) {

  LOG_DBG(stream, DBG_PARSER, "Try inserting packet...\n");
  uint64_t flow_key;

  if (pkt.ip_header.ip_p == IPPROTO_TCP) {
    flow_key = get_flow_key(pkt.ip_header.ip_src.s_addr, pkt.ip_header.ip_dst.s_addr, pkt.tcp.source, pkt.tcp.dest);
    LOG_DBG(stream, DBG_PARSER,
      "IP Source: %u, IP Destination: %u\nPort Source: %u, Port Destination: %u\n"
      "TCP seq: %u, TCP length: %d, Try inserting TCP...\n", 
      pkt.ip_header.ip_src.s_addr, pkt.ip_header.ip_dst.s_addr, pkt.tcp.source, pkt.tcp.dest,
      pkt.tcp.seq, pkt.payload.data_len);
    insert_tcp_pkt(table, flow_key, pkt, stream);
    LOG_DBG(stream, DBG_PARSER, "Done inserting TCP\n");
  } 
  else if (pkt.ip_header.ip_p == IPPROTO_UDP) {
    flow_key = get_flow_key(pkt.ip_header.ip_src.s_addr, pkt.ip_header.ip_dst.s_addr, pkt.udp.source, pkt.udp.dest);
    LOG_DBG(stream, DBG_PARSER,
      "IP Source: %u, IP Destination: %u\n"
      "Port Source: %u, Port Destination: %u\n"
      "UDP length: %d, Try inserting UDP...\n", 
      pkt.ip_header.ip_src.s_addr, pkt.ip_header.ip_dst.s_addr, pkt.udp.source, pkt.udp.dest, 
      pkt.payload.data_len);
    insert_udp_pkt(table, flow_key, pkt, stream);
    LOG_DBG(stream, DBG_PARSER, "Done inserting UDP\n");
  } 
  else {
    LOG_DBG(stream, DBG_PARSER, "Try inserting packet: Nothing done (not TCP or UDP)\n");
  }
}

// insert tcp packet to flow
void insert_tcp_pkt(HashTable table, uint64_t flow_key, parsed_packet pkt, FILE* stream) {
  LOG_DBG(stream, DBG_PARSER, "Finding flowkey = %lu...\n", flow_key);
  flow_base_t *flow = search_flow(table, flow_key, stream);
  LOG_DBG(stream, DBG_PARSER, "Found flowkey\n");

  LOG_DBG(stream, flow && DBG_PARSER, "---BEFORE INSERTING---\n"
    "Checking flow status = %u\nChecking first seq = %u & %u\nBEFORE BEFORE = %u\n",
    flow->pkt_close_flow, flow->init_seq_up, flow->init_seq_down, get_list_size(flow->head_flow)
  );

  // Need a new flow
  if (flow == NULL || HAS_SYN_FLAG || (flow->pkt_close_flow/10 && flow->pkt_close_flow%10) ) {
    // Insert to flow-up when it has SYN (Flag = 0x002)
    if (HAS_SYN_ONLY) {
      LOG_DBG(stream, DBG_PARSER, "TCP flow not found, but SYN flag detected\n");

      flow_base_t new_flow = create_flow(pkt, stream);
      insert_new_flow(table, create_flow_node(flow_key, new_flow, stream));

      LOG_DBG(stream, DBG_PARSER,
        "TCP got the first flow-up packet\nChecking again flow status = %u\n"
        "Checking again init seq = %u & %u\nTracking seq = %u -> %u, ack = %u\n",
        new_flow.pkt_close_flow, new_flow.init_seq_up, new_flow.init_seq_down,
        new_flow.current_seq, new_flow.nxt_pkt_seq, new_flow.current_ack
      );
      // struct timespec time_syn[10]; int time_point = 0;
      // printf("Time of SYN =");
      // for (int iii = 1; iii < 6; iii++)
      //   printf("\t%lu", time_syn[iii].tv_nsec - time_syn[iii-1].tv_nsec);
      // printf("\n");
      //clock_gettime(CLOCK_REALTIME, &time_syn[time_point++]); //  0
      //clock_gettime(CLOCK_REALTIME, &time_syn[time_point++]); //  1
      //clock_gettime(CLOCK_REALTIME, &time_syn[time_point++]); //  2
      //clock_gettime(CLOCK_REALTIME, &time_syn[time_point++]); //  3
      //clock_gettime(CLOCK_REALTIME, &time_syn[time_point++]); //  4
      //clock_gettime(CLOCK_REALTIME, &time_syn[time_point++]); //  5
    }

    // Insert to flow-down when it has SYN+ACK (Flag = 0x012)
    else if (flow != NULL && flow->tail_flow == flow->head_flow && HAS_SYN_FLAG && HAS_ACK_FLAG) {
      flow->init_seq_down = pkt.tcp.seq;
      flow->pkt_close_flow = flow->pkt_close_flow / 10 * 10;
      flow->current_seq = flow->init_seq_down; //*new*//
      flow->current_ack = flow->nxt_pkt_seq; //*new*//
      flow->nxt_pkt_seq = flow->init_seq_down + 1; //*new*//
      flow->is_last_pkt_up = 0; //*new*//

      LOG_DBG(stream, DBG_PARSER, "SYN/ACK detected\n"
        "TCP got the first flow-down packet\nChecking again flow status = %u\n"
        "Checking again init seq = %u & %u\nTracking seq = %u -> %u, ack = %u\n",
        flow->pkt_close_flow, flow->init_seq_up, flow->init_seq_down,
        flow->current_seq, flow->nxt_pkt_seq, flow->current_ack
      );
    }

    // Exception
    else {
      LOG_DBG(stream, DBG_PARSER, "SYN not detected or flow closed...\n");
    }
  }

  // Insert to flow when it has FIN (Flag = 0x001, 0x011)
  else if (HAS_FIN_FLAG) {
    LOG_DBG(stream, DBG_PARSER, "FIN(ACK) detected, closing flow...\n");
  }

  // Insert to flow when it has RST (Flag = 0x004, 0x014)
  else if (HAS_RST_FLAG) {
    LOG_DBG(stream, DBG_PARSER, "RST(ACK) detected, flows are closing...\n");
  }

  // Insert to flow when it has payload, usually PUSH+ACK (Flag = 0x018)
  else if (pkt.payload.data_len > 0 && pkt.payload.data_len < 8192) {
    LOG_DBG(stream, DBG_PARSER, "Payload detected. Try inserting...\n");
    TRY_INSERT_FLOW;
  }

  // When it has ACK only (Flag = 0x010)
  else if (HAS_ACK_ONLY) {
    LOG_DBG(stream, DBG_PARSER, "ACK detected & no payload, temporarily ignoring...\n");
  }

  // Currently treated as unnecessary for payload.
  else {
    LOG_DBG(stream, DBG_PARSER, "Flag = %x\nPacket undefined, ignoring...\n", pkt.tcp.th_flags);
  }

  LOG_DBG(stream, DBG_PARSER && (flow != NULL), "---AFTER INSERTING---\n"
    "Checking again flow status = %u\nChecking again first seq = %u & %u\nAFTER AFTER = %u\n",
    flow->pkt_close_flow, flow->init_seq_up, flow->init_seq_down, get_list_size(flow->head_flow)
  );
  LOG_DBG(stream, DBG_PARSER, "End of insert function\n");
  return;
}

// insert udp packet to flow
void insert_udp_pkt(HashTable table, uint64_t flow_key, parsed_packet pkt, FILE* stream) {
  LOG_DBG(stream, DBG_PARSER, "Finding flowkey = %lu...\n", flow_key);
  flow_base_t *flow = search_flow(table, flow_key, stream);
  LOG_DBG(stream, DBG_PARSER, "Found flowkey\n");

  if (flow == NULL) {
    LOG_DBG(stream, DBG_PARSER, "UDP flow not found, creating new one\n");
    Node *new_pkt_node = create_payload_node(pkt, true);
    flow_base_t new_flow = create_flow(pkt, stream);

    LOG_DBG(stream, DBG_PARSER, "Try inserting UDP to flow...\n");
    insert_to_flow(new_pkt_node, FIRST, &(new_flow.head_flow), &(new_flow.tail_flow), stream); //*new*//

    LOG_DBG(stream, DBG_PARSER, "Try inserting UDP flow to table...\n");
    insert_new_flow(table, create_flow_node(flow_key, new_flow, stream));

    LOG_DBG(stream, DBG_PARSER, "New UDP flow created, done inserting UDP\n");
    inserted_packets += 1;
  } else {
    LOG_DBG(stream, DBG_PARSER, "Flow found, inserting UDP to flow...\n");
    Node *new_pkt_node = create_payload_node(pkt, is_packet_up(flow, pkt));
    insert_to_flow(new_pkt_node, FIRST, &(flow->head_flow), &(flow->tail_flow), stream); //*new*//
    flow->total_payload += pkt.payload.data_len; //*new*//

    LOG_DBG(stream, DBG_PARSER, "Flow found, done inserting UDP\n");
    inserted_packets += 1;
  }
  LOG_DBG(stream, DBG_PARSER, "End of insert function\n");
  return;
}

// create a node with a value of parsed_payload type
Node *create_payload_node(parsed_packet pkt, bool is_pkt_up) {

  Node *const node = malloc(sizeof(Node));
  assert(node != NULL);

  // allocate memory for value
  parsed_payload *value = malloc(sizeof(parsed_payload));
  assert(value != NULL);

  // allocate memory for payload
  // u_char* payload = pkt.payload.data;
  u_char *const payload = malloc(pkt.payload.data_len);
  memcpy(payload, pkt.payload.data, pkt.payload.data_len);

  // copy payload to value
  *value = (parsed_payload){.data = payload, .data_len = pkt.payload.data_len, .is_up = (uint16_t)is_pkt_up};

  // move packet data to node
  node->value = value;
  node->key = pkt.ip_header.ip_p == IPPROTO_TCP ? pkt.tcp.seq : 0;
  node->next = NULL;

  return node;
}

// create a node with a value of flow_base_t type
Node *create_flow_node(uint64_t key, flow_base_t flow, FILE* stream) {

  Node *const node = malloc(sizeof(Node));
  assert(node != NULL);

  // allocate memory for value
  node->value = malloc(sizeof(flow_base_t));
  assert(node->value != NULL);

  // copy value to the new node
  memcpy(node->value, &flow, sizeof(flow_base_t));

  node->key = key;
  node->next = NULL;
  return node;
}

// create new flow from packet info and initialize flow direction
flow_base_t create_flow(parsed_packet pkt, FILE* stream) {
  struct in_addr sip = pkt.ip_header.ip_src;
  struct in_addr dip = pkt.ip_header.ip_dst;

  return pkt.ip_header.ip_p == IPPROTO_TCP
    ? (flow_base_t){
      .sip = sip,
      .dip = dip,
      .sp= pkt.tcp.source,
      .dp= pkt.tcp.dest,
      .ip_proto = pkt.ip_header.ip_p,
      .init_seq_up = pkt.tcp.seq,
      .current_seq = pkt.tcp.seq,
      .nxt_pkt_seq = pkt.tcp.seq + 1,
      .current_ack = 0,
      .is_last_pkt_up = 1,
    } : (flow_base_t){
      .sip = sip,
      .dip = dip,
      .sp= pkt.udp.source,
      .dp= pkt.udp.dest,
      .ip_proto = pkt.ip_header.ip_p,
      .total_payload = pkt.payload.data_len,
    };
}

// return 1 if this is in the same flow with SYN packet, otherwise 0
bool is_packet_up(flow_base_t const *flow, parsed_packet pkt) {
  return pkt.ip_header.ip_src.s_addr == flow->sip.s_addr;
}

// get into hashtable to print payload
void print_hashtable(HashTable const table, FILE* stream) {
  LOG_DBG(stream, DBG_FLOW, "********* HASH TABLE (NON-EMPTY ONLY) *********\n");
  for (uint32_t i = 0; i < table.size; i++) {
    Node *head = table.lists[i];
    if (!head) continue;
    LOG_DBG(stream, DBG_FLOW, "Id [%d]: \n", i);
    print_flows(head, stream);
    LOG_DBG(stream, DBG_FLOW, "\n");
  }
}

// get into each ID to print payload
void print_flows(Node const *const head, FILE* stream) {
  const Node *scanner = head;

  while (scanner != NULL) {
    flow_base_t* temp_flow = (flow_base_t*)scanner->value;
    if (temp_flow) {
      LOG_DBG(stream, DBG_FLOW, "Key: %lu:\n", scanner->key);
      print_flow(*temp_flow, stream);
    }
    scanner = scanner->next;
  }
}

// print flow info and all payloads in that flow
void print_flow(flow_base_t flow, FILE* stream) {
  Node const *temp = flow.head_flow;
  if (!temp) return;
  // else if (flow.ip_proto == IPPROTO_TCP) {
  //   temp = temp->next->next;
  //   LOG_DBG(stream, DBG_FLOW, "Removing SYN...");
  //   pop_first_node(&(flow.head_flow));
  //   LOG_DBG(stream, DBG_FLOW, "Removed SYN...");
  //   pop_first_node(&(flow.head_flow));
  //   LOG_DBG(stream, DBG_FLOW, "Removed SYN/ACK...");
  // }

  // LOG_DBG(stream, DBG_FLOW, "\t|IP: %s <=> %s\n", inet_ntop(flow.sip), inet_ntop(flow.dip));
  // print ip addresses
  LOG_DBG(stream, DBG_FLOW, "\t|IP: %s ", inet_ntoa(flow.sip));
  LOG_DBG(stream, DBG_FLOW, "<=> %s, ", inet_ntoa(flow.dip));
  // print port
  LOG_DBG(stream, DBG_FLOW, "port: %u <=> %u\n", flow.sp, flow.dp);
  // print list of packets in the flow
  LOG_DBG(stream, DBG_FLOW, "\t|Number of packets = %u, ", get_list_size(temp));
  // print payload amount
  LOG_DBG(stream, DBG_FLOW, "total payload: %u bytes\n", flow.total_payload);
  // print protocol type
  LOG_DBG(stream, DBG_FLOW, "\t|Protocol: %s\n", flow.ip_proto == IPPROTO_TCP? "TCP": "UDP");


  while (!(!temp)) {
    if (!((parsed_payload *)temp->value)) {
      LOG_DBG(stream, DBG_FLOW, "\t\t[ERROR]\n");
      break;
    } else if (((parsed_payload *)temp->value)->data_len == 65535) {
      // LOG_DBG(stream, DBG_FLOW, "\t\t[Got in here?]\n");
      inserted_packets -= 1;
      filtered_packets += 1;
    } else {
      char const* direction = (((parsed_payload *)temp->value)->is_up? "[ UP ]": "[DOWN]");
      LOG_DBG(stream, DBG_FLOW, "\t\t%s Seq: %10lu, data size: %4u\n", direction, temp->key, ((parsed_payload *)temp->value)->data_len);
      print_payload(((parsed_payload *)temp->value)->data, ((parsed_payload *)temp->value)->data_len, stream);
      LOG_DBG(stream, DBG_PAYLOAD, "\t\t-----------------------------------------------------------------------\n");
    }

    if (!(temp->next)) {
      break;
    }
    else temp = temp->next;
  }
}

// print package payload data (avoid printing binary data)
void print_payload(u_char const *payload, int32_t payload_size, FILE* stream) {

  if (payload_size < 1) {
    LOG_DBG(stream, DBG_PAYLOAD, "ERROR: payload size = %u\n", payload_size);
    return;
  } 
  LOG_DBG(stream, DBG_PAYLOAD, "\n");

  int len = payload_size;
  int len_rem = payload_size;
  int line_width = 16; /* number of bytes per line */
  int line_len;
  int offset = 0; /* zero-based offset counter */
  u_char const *ch = payload;

  /* data fits on one line */
  if (len <= line_width) {
    print_hex_ascii_line(ch, len, offset, stream);
    return;
  }

  /* data spans multiple lines */
  for (;;) {
    /* compute current line length */
    line_len = line_width % len_rem;
    /* print line */
    print_hex_ascii_line(ch, line_len, offset, stream);
    /* compute total remaining */
    len_rem = len_rem - line_len;
    /* shift pointer to remaining bytes to print */
    ch = ch + line_len;
    /* add offset */
    offset = offset + line_width;
    /* check if we have line width chars or less */
    if (len_rem <= line_width) {
      /* print last line and get out */
      print_hex_ascii_line(ch, len_rem, offset, stream);
      break;
    }
  }

  return;
}

// print package payload data (hex form)
void print_hex_ascii_line(u_char const *const payload, int32_t len, int32_t offset, FILE* stream) {

  int gap;
  u_char const *ch;

  /* offset */
  LOG_DBG(stream, DBG_PAYLOAD, "\t\t%05d   ", offset);

  /* hex */
  ch = payload;
  for (int i = 0; i < len; i++) {
    LOG_DBG(stream, DBG_PAYLOAD, "%02x ", *ch);
    ch++;
    /* print extra space after 8th byte for visual aid */
    if (i == 7) LOG_DBG(stream, DBG_PAYLOAD, " ");
  }
  /* print space to handle line less than 8 bytes */
  if (len < 8) LOG_DBG(stream, DBG_PAYLOAD, " ");

  /* fill hex gap with spaces if not full line */
  if (len < 16) {
    gap = 16 - len;
    for (int i = 0; i < gap; i++) {
      LOG_DBG(stream, DBG_PAYLOAD, "   ");
    }
  }
  LOG_DBG(stream, DBG_PAYLOAD, "   ");

  /* ascii (if printable) */
  ch = payload;
  for (int i = 0; i < len; i++) {
    if (isprint(*ch)) {
      LOG_DBG(stream, DBG_PAYLOAD, "%c", *ch);
    } 
    else {
      LOG_DBG(stream, DBG_PAYLOAD, ".");
    }
    ch++;
  }
  LOG_DBG(stream, DBG_PAYLOAD, "\n");
  return;
}

// Append all payload into a string
char* payload_to_string(Node* flow_direction, uint32_t len_need) {
  uint32_t len = get_list_size(flow_direction);
  // uint32_t flen = (uint32_t)(((parsed_payload *)(flow_direction->value))->data_len);

  // LOG_SCR("Length needed: %u", len_need);
  char* ans = (char*)malloc((2 + len_need) * sizeof(char));
  // LOG_SCR("Malloc successful\n");

  Node *temp = flow_direction;
  uint32_t iter_ans = 0;
  for (uint16_t i = 0; i < len && temp != NULL; i++) {
    parsed_payload* temp_payload = ((parsed_payload *)temp->value);

    if (!temp || !temp_payload || !(char*)(temp_payload->data)) {
      LOG_SCR("Packet #%d/%d has Error!\n", 1+i, len);
      temp = temp->next;
      continue;
    }

    char* to_concat = (char*)(temp_payload->data);
    int32_t data_length = temp_payload->data_len;
    if (data_length < 1) {
      // LOG_SCR("Packet #%d/%d len %d!\n", 1+i, len, data_length);
    } else if (iter_ans > 0) {
      uint8_t need_separate = 0;
      if (need_separate) strcat(ans, "\t");
      strncat(ans, convert_payload(to_concat, data_length), data_length);
      iter_ans += data_length;
      // *(ans + iter_ans) = "?";
      // LOG_SCR("Packet #%d/%d len %d assigned successfully!\n", i+1, len, data_length);
    } else {
      sprintf(ans, "%s", convert_payload(to_concat, data_length));
      iter_ans += data_length;
      // LOG_SCR("Packet #%d/%d len %d assigned successfully!\n", i+1, len, data_length);
    }
    temp = temp->next;
  }
  free(temp);
  if (iter_ans < 1000) LOG_SCR("Current ans = \n\nvvvvv*****vvvvv\n(%s)\n^^^^^*****^^^^^\n\n", ans);

  return ans;
}

// Convert payload string to an array of printable characters.
char* convert_payload(char* payload, uint32_t length) {
  char* ans = (char*)malloc((2 + length) * sizeof(char));
  char* iter_char = payload;
  for (uint32_t i = 0; i < length; i++) {
    if (isprint(*iter_char) || isblank(*iter_char)) {
      *(ans + i) = *iter_char;
    } else if (isspace(*iter_char)) {
      *(ans + i) = (*iter_char == '\v' || *iter_char == '\f'? '\n': *iter_char);
    } else {
      *(ans + i) = '.';
    }
    iter_char++;
  }
  *(ans + length) = '\0';
  // LOG_SCR("Converted:<<(%s)>>", ans);
  return ans;
}
