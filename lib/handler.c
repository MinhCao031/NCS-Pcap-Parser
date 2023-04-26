#include "handler.h"

static guint8 debug_type[6] = {0,0,0,0,0,1};
const guint8 *DBG_CONSOLE   = &debug_type[0];
const guint8 *DBG_TIMER     = &debug_type[1];
const guint8 *DBG_PARSER    = &debug_type[2];
const guint8 *DBG_FLOW      = &debug_type[3];
const guint8 *DBG_PAYLOAD   = &debug_type[4];
const guint8 *DBG_DISSECT   = &debug_type[5];
FILE* LOG_PARSE = NULL;
FILE* LOG_FLOWS = NULL;
FILE* LOG_DISEC = NULL;

gint8 parse_arg(int argc, char *argv[]) {
  LOG_DISEC = fopen(FILE_DISEC, "a+");
  gint8 ans = 0;
  gint8 opt;
  while ((opt = getopt(argc, argv, "ctpfds")) != -1) {
    switch (opt) {
      case 'c': {
        debug_type[0] = 1;
        DBG_CONSOLE = &debug_type[0];
        ans++; break;
      }
      case 't': {
        debug_type[1] = 1;
        DBG_TIMER   = &debug_type[1];
        LOG_PARSE   = fopen(FILE_PARSE, "a+");
        ans++; break;
      }
      case 'p': {
        debug_type[2] = 1;
        DBG_PARSER  = &debug_type[2];
        LOG_PARSE   = fopen(FILE_PARSE, "a+");
        ans++; break;
      }
      case 'f': {
        debug_type[3] = 1;
        DBG_FLOW    = &debug_type[3];
        LOG_FLOWS   = fopen(FILE_FLOWS, "a+");
        ans++; break;
      }
      case 'd': {
        DBG_PAYLOAD = &debug_type[3];
        ans++; break;
      }
      default : {
        printf("Usage of running C file: %s [-c] [-t] [-p] [-f] [-d] pcap_file_name\n"
          "-c to print something to the console\n"
          "-t to log the timer\n"
          "-p to log the parsing process\n"
          "-f to log the info of every flows\n"
          "-d to log the payload of packets (Require \"-f\")\n"
          "pcap_file_name is required to run\n", argv[0]
        );
        return -1;
        break;
      }
    }
  }
  return ans;
}

guint64 get_flow_key(guint64 ip1, guint64 ip2, guint64 p1, guint64 p2) {
  guint64 side1 = ip1 + p1 * POW2(16);
  guint64 side2 = ip2 + p2 * POW2(16);
  guint64 large = side1 > side2? side1: side2;
  guint64 small = side1 < side2? side1: side2;
  guint64 ans = large * (large + 1) / 2 + small + 1;
  return ans;
}

guint64 get_side_port_ip(guint16 port, guint32 ip) {
  guint64 ans = ip;
  ans += POW2(32) * port;
  return ans;
}

// classify and insert a new packet into hash table
void insert_packet(HashTable table, parsed_packet pkt, FILE* stream) {
  if (pkt.ip_header.ip_p == IPPROTO_TCP) {
    LOG_DBG(stream, *DBG_PARSER,
      "IP Source: %u, IP Destination: %u\nPort Source: %u, Port Destination: %u\n"
      "TCP seq: %u, TCP length: %d\n", 
      pkt.ip_header.ip_src.s_addr, pkt.ip_header.ip_dst.s_addr, pkt.tcp.source, pkt.tcp.dest,
      pkt.tcp.seq, pkt.payload.data_len);
    insert_tcp_pkt(table, pkt, stream);
  } 
  else if (pkt.ip_header.ip_p == IPPROTO_UDP) {
    LOG_DBG(stream, *DBG_PARSER,
      "IP Source: %u, IP Destination: %u\n"
      "Port Source: %u, Port Destination: %u\n"
      "UDP length: %d\n", 
      pkt.ip_header.ip_src.s_addr, pkt.ip_header.ip_dst.s_addr, pkt.udp.source, pkt.udp.dest, 
      pkt.payload.data_len);
    insert_udp_pkt(table, pkt, stream);
  }
  else {
    LOG_DBG(stream, *DBG_PARSER, "Try inserting packet: Nothing done (not TCP or UDP)\n");
  }
}

// insert tcp packet to flow
void insert_tcp_pkt(HashTable table, parsed_packet pkt, FILE* stream) {
  guint64 flow_key = get_flow_key(pkt.ip_header.ip_src.s_addr, pkt.ip_header.ip_dst.s_addr, pkt.tcp.source, pkt.tcp.dest);
  LOG_DBG(stream, *DBG_PARSER, "Finding flowkey = %lu...\n", flow_key);
  flow_base_t *flow = search_flow(table, flow_key, stream);

  LOG_DBG(stream, flow && *DBG_PARSER, "Checking seq = UP(%u->%u) & DOWN(%u->%u)\n",
    flow->init_seq[1], flow->next_seq[1], flow->init_seq[0], flow->next_seq[0]
  );

  // Need a new flow
  if (flow == NULL || HAS_SYN_FLAG) {
    // Insert to flow-up when it has SYN (Flag = 0x002)
    if (HAS_SYN_ONLY && flow == NULL) {
      LOG_DBG(stream, *DBG_PARSER, "TCP flow not found, but SYN flag detected\n");

      flow_base_t new_flow = create_flow(pkt, stream);
      insert_new_flow(table, create_flow_node(flow_key, new_flow));

      LOG_DBG(stream, *DBG_PARSER,
        "TCP got the first flow-up packet\n"
        "Checking again init seq = %u & %u\nTracking seq = %u -> %u, ack = %u\n",
        new_flow.init_seq[1], new_flow.init_seq[0],
        pkt.tcp.seq, new_flow.next_seq[1], new_flow.next_seq[0]
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
    else if (flow != NULL && flow->head_flow == NULL && HAS_ACK_FLAG) {
      flow->init_seq[0] = pkt.tcp.seq;
      flow->next_seq[0] = flow->init_seq[0] + 1; //*new*//

      LOG_DBG(stream, *DBG_PARSER, "SYN/ACK detected\n"
        "Checking again init seq = %u & %u\nTracking seq = %u -> %u, ack = %u\n",
        flow->init_seq[1], flow->init_seq[0], pkt.tcp.seq, flow->next_seq[0], flow->next_seq[1]
      );
    }

    // Exception 1
    else if (HAS_SYN_FLAG) {
      LOG_DBG(stream, *DBG_PARSER, "Weird SYN packet with flag = %x\n", pkt.tcp.th_flags);
      LOG_DBG(stream, pkt.payload.data_len > 0, "PACKET #%u HAS SYN+PSH -> SUSPICIOUS!!!\n", captured_packets);
    }

    // Exception 2
    else {
      LOG_DBG(stream, *DBG_PARSER, "No flow flound\n");
    }
  }

  // Insert to flow when it has FIN (Flag = 0x001, 0x011)
  else if (HAS_FIN_FLAG) {
    LOG_DBG(stream, *DBG_PARSER, "FIN(ACK) detected, closing flow...\n");
  }

  // Insert to flow when it has RST (Flag = 0x004, 0x014)
  else if (HAS_RST_FLAG) {
    LOG_DBG(stream, *DBG_PARSER, "RST(ACK) detected, flows are closing...\n");
  }

  // Insert to flow when it has payload, usually PUSH+ACK (Flag = 0x018)
  else if (pkt.payload.data_len > 0 && pkt.payload.data_len < 64241) {
    LOG_DBG(stream, *DBG_PARSER, "Payload detected. Try inserting...\n");
    VERIFY_SEQ;
    TRY_INSERT_FLOW;
    VERIFY_SEQ;
    // PAYLOAD_PARSER;
  }

  // When it has ACK only (Flag = 0x010)
  else if (HAS_ACK_ONLY) {
    LOG_DBG(stream, *DBG_PARSER, "ACK detected & no payload, temporarily ignoring...\n");
  }

  // Currently treated as unnecessary for payload.
  else {
    LOG_DBG(stream, *DBG_PARSER, "Flag = %x\nPacket undefined, ignoring...\n", pkt.tcp.th_flags);
  }

  LOG_DBG(stream, *DBG_PARSER && (flow != NULL), "Checking again first seq = UP(%u->%u) & DOWN(%u->%u)\n",
    flow->init_seq[1], flow->next_seq[1], flow->init_seq[0], flow->next_seq[0]
  );

  if(flow != NULL) {
    LOG_DBG(stream, *DBG_PARSER, "Checking pointers:\n");
    LOG_DBG(stream, *DBG_PARSER && (flow->head_flow != NULL), "Head -> %lu\n", flow->head_flow->key);
    LOG_DBG(stream, *DBG_PARSER && (flow->tail_flow != NULL), "Tail -> %lu\n", flow->tail_flow->key);
    LOG_DBG(stream, *DBG_PARSER && (flow->track_flow[1] != NULL), "UP -> %lu\n", flow->track_flow[1]->key);
    LOG_DBG(stream, *DBG_PARSER && (flow->track_flow[0] != NULL), "DOWN -> %lu\n", flow->track_flow[0]->key);  \
  }

  return;
}

// insert udp packet to flow
void insert_udp_pkt(HashTable table, parsed_packet pkt, FILE* stream) {
  guint64 flow_key = get_flow_key(pkt.ip_header.ip_src.s_addr, pkt.ip_header.ip_dst.s_addr, pkt.udp.source, pkt.udp.dest);
  LOG_DBG(stream, *DBG_PARSER, "Finding flowkey = %lu...\n", flow_key);
  flow_base_t *flow = search_flow(table, flow_key, stream);

  if (flow == NULL) {
    LOG_DBG(stream, *DBG_PARSER, "UDP flow not found, creating new one\n");
    Node *new_pkt_node = create_payload_node(pkt, true, 0);
    flow_base_t new_flow = create_flow(pkt, stream);

    LOG_DBG(stream, *DBG_PARSER, "Try inserting UDP to flow...\n");
    insert_to_flow(new_pkt_node, LAST, &new_flow, stream); //*new*//

    LOG_DBG(stream, *DBG_PARSER, "Try inserting UDP flow to table...\n");
    insert_new_flow(table, create_flow_node(flow_key, new_flow));

    LOG_DBG(stream, *DBG_PARSER, "New UDP flow created, done inserting UDP\n");
    inserted_packets += 1;
  } else {
    LOG_DBG(stream, *DBG_PARSER, "Flow found, inserting UDP to flow...\n");
    Node *new_pkt_node = create_payload_node(pkt, is_packet_up(flow, pkt), 0);
    insert_to_flow(new_pkt_node, LAST, flow, stream); //*new*//
    flow->total_payload += pkt.payload.data_len; //*new*//

    LOG_DBG(stream, *DBG_PARSER, "Flow found, done inserting UDP\n");
    inserted_packets += 1;
  }
  LOG_DBG(stream, *DBG_PARSER, "End of insert function\n");
  return;
}

// create a node with a value of parsed_payload type
Node *create_payload_node(parsed_packet pkt, bool is_pkt_up, guint32 skip_byte) {

  Node *const node = malloc(sizeof(Node));
  assert(node != NULL);

  // allocate memory for value
  parsed_payload *value = malloc(sizeof(parsed_payload));
  assert(value != NULL);

  // allocate memory for payload
  assert(pkt.payload.data_len - skip_byte > 0);
  u_char *const payload = malloc(pkt.payload.data_len - skip_byte);

  memcpy(payload, pkt.payload.data + skip_byte, pkt.payload.data_len - skip_byte);

  // copy payload to value
  *value = (parsed_payload){
    .index = captured_packets,
    .data_len = pkt.payload.data_len - skip_byte,
    .is_up = (guint16)is_pkt_up,
    .is_truncated = skip_byte > 0? 1: 0,
    .data = payload
  };

  // move packet data to node
  node->value = value;
  node->key = pkt.ip_header.ip_p == IPPROTO_TCP ? pkt.tcp.seq : 0;
  node->next = NULL;

  return node;
}

// create a node with a value of flow_base_t type
Node *create_flow_node(guint64 key, flow_base_t flow) {

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
      .sip =            sip,
      .dip =            dip,
      .sp =             pkt.tcp.source,
      .dp =             pkt.tcp.dest,
      .spip =           get_side_port_ip(pkt.tcp.source, sip.s_addr),
      .dpip =           get_side_port_ip(pkt.tcp.dest  , dip.s_addr),
      .ip_proto =       pkt.ip_header.ip_p,
      .init_seq =       {0, pkt.tcp.seq},
      .next_seq =       {0, pkt.tcp.seq + 1},
      .track_flow =     calloc(2, sizeof(Node*)),
      .flow_key =       get_flow_key(sip.s_addr, dip.s_addr, pkt.tcp.source, pkt.tcp.dest),
    } : (flow_base_t){
      .sip =            sip,
      .dip =            dip,
      .sp =             pkt.udp.source,
      .dp =             pkt.udp.dest,
      .spip =           get_side_port_ip(pkt.tcp.source, sip.s_addr),
      .dpip =           get_side_port_ip(pkt.tcp.dest  , dip.s_addr),
      .ip_proto =       pkt.ip_header.ip_p,
      .init_seq =       {0, 0},
      .next_seq =       {0, 0},
      .total_payload =  pkt.payload.data_len,
      .track_flow =     calloc(2, sizeof(Node*)),
      .flow_key =       get_flow_key(sip.s_addr, dip.s_addr, pkt.udp.source, pkt.udp.dest),
    };
}

// return 1 if this is in the same flow with SYN packet, otherwise 0
bool is_packet_up(flow_base_t const *flow, parsed_packet pkt) {
  return pkt.ip_header.ip_src.s_addr == flow->sip.s_addr;
}

// get into hashtable to print payload
void print_hashtable(HashTable const table, FILE* stream) {
  LOG_DBG(stream, *DBG_FLOW, "********* HASH TABLE (NON-EMPTY ONLY) *********\n");
  for (guint32 i = 0; i < table.size; i++) {
    Node *head = table.lists[i];
    if (!head) continue;
    LOG_DBG(stream, *DBG_FLOW, "Id [%d]: \n", i);
    print_flows(head, stream);
    LOG_DBG(stream, *DBG_FLOW, "\n");
  }
}

// get into each ID to print payload
void print_flows(Node const *const head, FILE* stream) {
  const Node *scanner = head;

  while (scanner != NULL) {
    flow_base_t* temp_flow = (flow_base_t*)scanner->value;
    if (temp_flow) print_flow(*temp_flow, stream);
    scanner = scanner->next;
  }
}

// print flow info and all payloads in that flow
void print_flow(flow_base_t flow, FILE* stream) {
  Node const *temp = flow.head_flow;
  if (!temp) return;

  LOG_DBG(stream, *DBG_FLOW, "Key: %lu:\n\tCheck seq: UP(%u->%u) DOWN(%u->%u)\n",
          flow.flow_key, flow.init_seq[1], flow.next_seq[1],
          flow.init_seq[0], flow.next_seq[0]
  );
  // LOG_DBG(stream, *DBG_FLOW, "\tCheck IP: UP(%X) DOWN(%X)\n",
  //         flow.sip.s_addr, flow.dip.s_addr
  // );

  // print ip addresses
  LOG_DBG(stream, *DBG_FLOW, "\t|IP: %s ", inet_ntoa(flow.sip));
  LOG_DBG(stream, *DBG_FLOW, "<=> %s, ", inet_ntoa(flow.dip));
  // print port
  LOG_DBG(stream, *DBG_FLOW, "port: %u <=> %u\n", flow.sp, flow.dp);
  // print list of packets in the flow
  LOG_DBG(stream, *DBG_FLOW, "\t|Number of packets = %u, ", get_list_size(temp));
  // print payload amount
  LOG_DBG(stream, *DBG_FLOW, "total payload: %u bytes\n", flow.total_payload);
  // print protocol type
  LOG_DBG(stream, *DBG_FLOW, "\t|Protocol: %s\n", flow.ip_proto == IPPROTO_TCP? "TCP": "UDP");


  while (temp) {
    if (!PP_IN_NODE(temp)) {
      LOG_DBG(stream, *DBG_FLOW, "\t\t[ERROR]\n");
      break;
    } else {
      char const* direction = (PP_IN_NODE(temp)->is_up? "[ UP ]": "[DOWN]");
      LOG_DBG(stream, *DBG_FLOW, "\t\tp%-7u%s Seq:%11lu, data size:%6u%s", PP_IN_NODE(temp)->index,
              direction, temp->key, PP_IN_NODE(temp)->data_len,
              PP_IN_NODE(temp)->is_truncated? " (truncated)\n": "\n"
      );
      print_payload(PP_IN_NODE(temp)->data, PP_IN_NODE(temp)->data_len, stream);
      LOG_DBG(stream, *DBG_PAYLOAD, "\t\t-----------------------------------------------------------------------\n");
    }

    if (!(temp->next)) {
      break;
    }
    else temp = temp->next;
  }
}

// print package payload data (avoid printing binary data)
void print_payload(u_char const *payload, gint32 payload_size, FILE* stream) {
  if (payload_size < 1) {
    LOG_DBG(stream, *DBG_PAYLOAD, "ERROR: payload size = %u\n", payload_size);
    return;
  }
  LOG_DBG(stream, *DBG_PAYLOAD, "\n");

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
void print_hex_ascii_line(u_char const *const payload, gint32 len, gint32 offset, FILE* stream) {
  int gap;
  u_char const *ch;

  /* offset */
  LOG_DBG(stream, *DBG_PAYLOAD, "\t\t%05d   ", offset);

  /* hex */
  ch = payload;
  for (int i = 0; i < len; i++) {
    LOG_DBG(stream, *DBG_PAYLOAD, "%02x ", *ch);
    ch++;
    /* print extra space after 8th byte for visual aid */
    LOG_DBG(stream, *DBG_PAYLOAD && i == 7, " ");
  }
  /* print space to handle line less than 8 bytes */
  LOG_DBG(stream, *DBG_PAYLOAD && len < 8, " ");

  /* fill hex gap with spaces if not full line */
  gap = 16 - len;
  for (int i = -1; i < gap; i++) {
    LOG_DBG(stream, *DBG_PAYLOAD, "   ");
  }

  /* ascii (if printable) */
  ch = payload;
  for (int i = 0; i < len; i++) {
    LOG_DBG(stream, *DBG_PAYLOAD, "%c", (isprint(*ch)? *ch: '.'));
    ch++;
  }
  LOG_DBG(stream, *DBG_PAYLOAD, "\n");
  return;
}

// Append all payload into a string
char* payload_to_string(Node* flow_direction, guint32 len_need) {
  guint32 len = get_list_size(flow_direction);

  // LOG_SCR("Length needed: %u", len_need);
  char* ans = (char*)malloc((2 + len_need) * sizeof(char));
  // LOG_SCR("Malloc successful\n");

  Node *temp = flow_direction;
  guint32 iter_ans = 0;
  for (guint16 i = 0; i < len && temp != NULL; i++) {
    parsed_payload* temp_payload = PP_IN_NODE(temp);

    if (!temp || !temp_payload || !(char*)(temp_payload->data)) {
      LOG_SCR("Packet #%d/%d has Error!\n", 1+i, len);
      temp = temp->next;
      continue;
    }

    char* to_concat = (char*)(temp_payload->data);
    gint32 data_length = temp_payload->data_len;
    if (data_length < 1) {
      // LOG_SCR("Packet #%d/%d len %d!\n", 1+i, len, data_length);
    } else if (iter_ans > 0) {
      guint8 need_separate = 0;
      if (need_separate) strcat(ans, "\t");
      strncat(ans, convert_payload(to_concat, data_length), data_length);
      iter_ans += data_length;
      // LOG_SCR("Packet #%d/%d len %d assigned successfully!\n", i+1, len, data_length);
    } else {
      sprintf(ans, "%s", convert_payload(to_concat, data_length));
      iter_ans += data_length;
      // LOG_SCR("Packet #%d/%d len %d assigned successfully!\n", i+1, len, data_length);
    }
    temp = temp->next;
  }
  free(temp);
  LOG_SCR("Current ans = \n\nvvvvv*****vvvvv\n(%s)\n^^^^^*****^^^^^\n\n", ans);

  return ans;
}

// Convert payload string to an array of printable characters.
char* convert_payload(char* payload, guint32 length) {
  char* ans = (char*)malloc((2 + length) * sizeof(char));
  char* iter_char = payload;
  for (guint32 i = 0; i < length; i++) {
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
