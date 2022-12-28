#include <assert.h>
#include <string.h>
#include "handler.h"
#include "log.h"

int inserted_packets = 0;

uint64_t get_flow_key(uint64_t ip1, uint64_t ip2, uint64_t p1, uint64_t p2) {
  uint64_t half64 = 2147483648;
  uint64_t ans = ip1 + ip2 + (p1*p1 - p1*p2 + p2*p2) * half64;
  return ans;
}

// classify and insert a new packet into hash table
void insert_packet(HashTable table, parsed_packet pkt, FILE* stream) {

  LOG_DBG(stream, DBG_PARSER, "Try inserting packet...\n");

  uint64_t flow_key;

  if (pkt.ip_header.ip_p == IPPROTO_TCP) {
    flow_key = get_flow_key(pkt.ip_header.ip_src.s_addr, pkt.ip_header.ip_dst.s_addr, pkt.tcp.source, pkt.tcp.dest);
    LOG_DBG(stream, DBG_PARSER,
      "IP Source: %u\nIP Destination: %u\nPort Source: %u\nPort Destination: %u\n"
      "TCP seq: %u\nTCP length: %d\nTry inserting TCP...\n", 
      pkt.ip_header.ip_src.s_addr, pkt.ip_header.ip_dst.s_addr, pkt.tcp.source, pkt.tcp.dest,
      pkt.tcp.seq, pkt.payload.data_len);
    insert_tcp_pkt(table, flow_key, pkt, stream);
    LOG_DBG(stream, DBG_PARSER, "Done inserting TCP\n");/**/
  } 
  else if (pkt.ip_header.ip_p == IPPROTO_UDP) {
    flow_key = get_flow_key(pkt.ip_header.ip_src.s_addr, pkt.ip_header.ip_dst.s_addr, pkt.udp.source, pkt.udp.dest);
    LOG_DBG(stream, DBG_PARSER,
      "IP Source: %u\nIP Destination: %u\n"
      "Port Source: %u\nPort Destination: %u\n"
      "UDP length: %d\nTry inserting UDP...\n", 
      pkt.ip_header.ip_src.s_addr, pkt.ip_header.ip_dst.s_addr, pkt.udp.source, pkt.udp.dest, 
      pkt.payload.data_len);
    insert_udp_pkt(table, flow_key, pkt, stream);
    LOG_DBG(stream, DBG_PARSER, "Done inserting UDP\n");/**/
  } 
  else {
    LOG_DBG(stream, DBG_PARSER, "Try inserting packet: Nothing done (not TCP or UDP)\n");/**/
  }
}

// insert tcp packet to flow
void insert_tcp_pkt(HashTable table, uint64_t flow_key, parsed_packet pkt, FILE* stream) {
  LOG_DBG(stream, DBG_PARSER, "Finding flowkey = %ld...\n", flow_key);/**/
  flow_base_t *flow = search_flow(table, flow_key, stream);
  LOG_DBG(stream, DBG_PARSER, "Found flowkey\n");/**/
  LOG_DBG(stream, DBG_PARSER, "Flag = %x\n", pkt.tcp.th_flags);/**/

  // Eliminate spurious packet with weird length
  if ((int) pkt.payload.data_len < 0 || (int) pkt.payload.data_len > 65535) {
    LOG_DBG(stream, DBG_PARSER, "ERROR length = %d -> Exitting...\n", pkt.payload.data_len);
    return;
  } 
  // Insert to flow-up when it's a SYN (Flag = 0x002)
  else if (flow == NULL) {
    LOG_DBG(stream, DBG_PARSER, "TCP flow not found, creating new one if it is SYN...\n");/**/

    if (pkt.tcp.th_flags == TH_SYN) { 
      flow_base_t new_flow = create_flow(pkt, stream);
      new_flow.exp_seq_up = pkt.tcp.seq + 1;
      insert_new_flow(table, create_flow_node(flow_key, new_flow, stream));
      LOG_DBG(stream, DBG_PARSER, "New TCP flow-up created\n");/**/
    } 
    else {
      LOG_DBG(stream, DBG_PARSER, "Packet is not SYN, ignoring...\n");/**/
    }
  }
  // Insert to flow-down when it's a SYN/ACK (Flag = 0x012)
  else if (pkt.tcp.th_flags == 0x12) {
    LOG_DBG(stream, DBG_PARSER, "SYN/ACK detected\n");
    Node *new_pkt_node = create_payload_node(pkt, stream);
    flow->exp_seq_down = pkt.tcp.seq + 1;
    insert_to_flow(new_pkt_node, DESC, &(flow->flow_down), stream);
  }
  // Insert to flow when it has data (Flag = 0x018)
  else if (pkt.tcp.th_flags == 0x18 || pkt.payload.data_len > 6) {
    Node *new_pkt_node = create_payload_node(pkt, stream);
    LOG_DBG(stream, DBG_PARSER, "Flow found, inserting TCP to flow...\n");/**/
    if (get_flow_direction(flow, pkt, stream) == &(flow->flow_up)) {
      LOG_DBG(stream, DBG_PARSER, "UP...\n");
      LOG_DBG(stream, DBG_PARSER, "Checking up seq = %u...\n", flow->exp_seq_up);
      LOG_DBG(stream, DBG_PARSER, "Checking real seq = %u...\n", pkt.tcp.seq);
      if (DBG_PKT_SEQ || flow->exp_seq_up == pkt.tcp.seq) {
        LOG_DBG(stream, DBG_PARSER, "CHECK: EQUAL\n");
        flow->exp_seq_up += ((parsed_payload *)new_pkt_node->value)->data_len;
        insert_to_flow(new_pkt_node, DESC, &(flow->flow_up), stream);
        LOG_DBG(stream, DBG_PARSER, "Flow found, done inserting TCP\n");/**/
        LOG_DBG(stream, DBG_PARSER, "Expected Seq UP/DOWN = %u, %u\n", flow->exp_seq_up, flow->exp_seq_down);/**/
        inserted_packets += 1;
      } 
      else {
        LOG_DBG(stream, DBG_PARSER, "CHECK: NOT EQUAL\n");
        insert_to_wait(&flow->wait_up, new_pkt_node, stream);
        LOG_DBG(stream, DBG_PARSER, "INSERTED TO WAIT LIST +01\n")
        LOG_DBG(stream, DBG_PARSER, "******** WAITING LIST #+1 *****\n");
        print_flow_direction(flow->wait_down, true, stream);
      }
    } 
    else if (get_flow_direction(flow, pkt, stream) == &(flow->flow_down)) {
      LOG_DBG(stream, DBG_PARSER, "DOWN...\n");
      LOG_DBG(stream, DBG_PARSER, "Checking down seq = %u...\n", flow->exp_seq_down);
      LOG_DBG(stream, DBG_PARSER, "Checking real seq = %u...\n", pkt.tcp.seq);
      if (DBG_PKT_SEQ || flow->exp_seq_down == pkt.tcp.seq) {
        LOG_DBG(stream, DBG_PARSER, "CHECK: EQUAL\n");
        flow->exp_seq_down += ((parsed_payload *)new_pkt_node->value)->data_len;
        insert_node_desc(&(flow->flow_down), new_pkt_node, stream);
        /* Check the waiting list again */
        while (NULL != flow->wait_down) {
          LOG_DBG(stream, DBG_PARSER, "******** WAITING LIST #1 *****\n");
          print_flow_direction(flow->wait_down, true, stream);
          LOG_DBG(stream, DBG_PARSER, "Inserted 1 TCP packet\nExpect next seq = %u\n", flow->exp_seq_down);
          Node* extra_pkt_node = search_node(flow->wait_down, flow->exp_seq_down);
          if (!extra_pkt_node) break;
          // Node extra_pkt = *extra_pkt_node;
          uint32_t payload_len = ((parsed_payload *)extra_pkt_node->value)->data_len;
          LOG_DBG(stream, DBG_PARSER, "***Looping with len = %u...***\n", payload_len);
          flow->exp_seq_down += payload_len;
          // insert_to_flow(extra_pkt_node, DESC, &(flow->flow_down), stream);
          // delete_node(&flow->wa it_down, flow->exp_seq_down - payload_len, stream);
          insert_node_desc(&(flow->flow_down), extra_pkt_node, stream);
          LOG_DBG(stream, DBG_PARSER, "******** WAITING LIST #2 *****\n");
          print_flow_direction(flow->wait_down, true, stream);
          inserted_packets += 1;
        }
        /* Done with the waiting list */      
        LOG_DBG(stream, DBG_PARSER, "Flow found, done inserting TCP\n");/**/
        LOG_DBG(stream, DBG_PARSER, "Expected Seq UP/DOWN = %u, %u\n", flow->exp_seq_up, flow->exp_seq_down);/**/
        inserted_packets += 1;
      } 
      else if (pkt.payload.data_len > 6) {
        LOG_DBG(stream, DBG_PARSER, "CHECK: NOT EQUAL\n");
        insert_to_wait(&flow->wait_down, new_pkt_node, stream);
        LOG_DBG(stream, DBG_PARSER, "INSERTED TO WAIT LIST -01\n")
        LOG_DBG(stream, DBG_PARSER, "******** WAITING LIST #-1 *****\n");
        print_flow_direction(flow->wait_down, true, stream);
      }        
    } 
    else if (pkt.payload.data_len > 6) {
      LOG_DBG(stream, DBG_PARSER, "UNEXPECTED!!!");
    }
  } 
  // Normally flag = 0x010 or Package error
  else {
    LOG_DBG(stream, DBG_PARSER, "Nothing done, maybe this is unnecessary processing packets\n");
  }
  LOG_DBG(stream, DBG_PARSER, "End of insert function\n");
}

// insert udp packet to flow
void insert_udp_pkt(HashTable table, uint64_t flow_key, parsed_packet pkt, FILE* stream) {
  LOG_DBG(stream, DBG_PARSER, "Finding flowkey = %ld...\n", flow_key);/**/
  flow_base_t *flow = search_flow(table, flow_key, stream);
  LOG_DBG(stream, DBG_PARSER, "Found flowkey\n");/**/

  Node *new_pkt_node = create_payload_node(pkt, stream);

  if (flow == NULL) {
    LOG_DBG(stream, DBG_PARSER, "UDP flow not found, creating new one\n");/**/
    flow_base_t new_flow = create_flow(pkt, stream);

    LOG_DBG(stream, DBG_PARSER, "Try inserting UDP to flow...\n");/**/
    insert_to_flow(new_pkt_node, FIRST, get_flow_direction(&new_flow, pkt, stream), stream);

    LOG_DBG(stream, DBG_PARSER, "Try inserting UDP flow to table...\n");/**/
    insert_new_flow(table, create_flow_node(flow_key, new_flow, stream));

    LOG_DBG(stream, DBG_PARSER, "New UDP flow created, done inserting UDP\n");/**/
    inserted_packets += 1;
  } 
  else {
    LOG_DBG(stream, DBG_PARSER, "Flow found, inserting UDP to flow...\n");/**/
    insert_to_flow(new_pkt_node, FIRST, get_flow_direction(flow, pkt, stream), stream);

    LOG_DBG(stream, DBG_PARSER, "Flow found, done inserting UDP\n");/**/
    inserted_packets += 1;
  }
}

// print the hash table
void print_hashtable(HashTable const table, FILE* stream) {

  LOG_DBG(stream, DBG_PARSER, "********* HASH TABLE *********\n");
  for (uint i = 0; i < table.size; i++) {
    Node *head = table.lists[i];
    LOG_DBG(stream, DBG_PARSER, "Id [%d]: \n", i);
    print_flows(head, stream);
    LOG_DBG(stream, DBG_PARSER, "\n");
  }
}

void print_flows(Node const *const head, FILE* stream) {

  const Node *scaner = head;

  
  while (scaner != NULL) {
    LOG_DBG(stream, DBG_PARSER, "Key: %lu:\n", scaner->key);
    print_flow(*(flow_base_t *)scaner->value, stream);
    scaner = scaner->next;
  }
}

// print flow info like src ip, dst ip, src port, dst port, protocol and payload
void print_flow(flow_base_t flow, FILE* stream) {
  // print ip addresses
  LOG_DBG(stream, DBG_PARSER, "\t|ip: %s", inet_ntoa(flow.sip));
  LOG_DBG(stream, DBG_PARSER, " <=> %s, ", inet_ntoa(flow.dip));

  // print port
  LOG_DBG(stream, DBG_PARSER, "port: %d", flow.sp);
  LOG_DBG(stream, DBG_PARSER, " <=> %d\n", flow.dp);

  if (flow.ip_proto == IPPROTO_TCP) {
    LOG_DBG(stream, DBG_PARSER, "\t|Protocol: TCP\n");

    // print expected sequence number
    LOG_DBG(stream, DBG_PARSER, "\t|exp seq DOWN: %u, ", flow.exp_seq_down);
    LOG_DBG(stream, DBG_PARSER, "exp seq UP: %u\n", flow.exp_seq_up);
  } 
  else {
    LOG_DBG(stream, DBG_PARSER, "\t|Protocol: UDP\n");
  }

  // print list of packets in the flow
  print_flow_direction(flow.flow_up, true, stream);
  print_flow_direction(flow.flow_down, false, stream);
  LOG_DBG(stream, DBG_PARSER, "\t|Waiting list:\n")
  print_flow_direction(flow.wait_up, true, stream);
  print_flow_direction(flow.wait_down, false, stream);
}

// print payload in a flow direction
void print_flow_direction(Node const *head, bool is_up, FILE* stream) {

  Node const *temp = head;
  char const *direction = is_up ? "UP" : "DOWN";

  while (temp != NULL) {

    LOG_DBG(stream, DBG_PARSER, "\t\t[%s] ", direction);
    LOG_DBG(stream, DBG_PARSER, "Seq: %ld, data size: %d\n", temp->key,
           ((parsed_payload *)temp->value)->data_len);

	//// print_payload(((parsed_payload *)temp->value)->data, ((parsed_payload *)temp->value)->data_len, stream);
	//// fprintf(stream, "\t\t-----------------------------------------------------------------------\n");

    temp = temp->next;
  }
}


// create new packet node
Node *create_payload_node(parsed_packet pkt, FILE* stream) {

  Node *const node = malloc(sizeof(Node));
  assert(node != NULL);

  // allocate memory for value
  parsed_payload *value = malloc(sizeof(parsed_payload));
  assert(value != NULL);

  // allocate memory for payload
  u_char *const payload = malloc(pkt.payload.data_len);
  memcpy(payload, pkt.payload.data, pkt.payload.data_len);

  // copy payload to value
  *value = (parsed_payload){.data = payload, .data_len = pkt.payload.data_len};

  // move packet data to node
  node->value = value;
  node->key = pkt.ip_header.ip_p == IPPROTO_TCP ? pkt.tcp.seq : 0;
  node->next = NULL;

  return node;
}

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

  return pkt.ip_header.ip_p == IPPROTO_TCP
			 ? (flow_base_t){
				   .sip = pkt.ip_header.ip_src,
				   .dip = pkt.ip_header.ip_dst,
				   .sp= pkt.tcp.source,
				   .dp= pkt.tcp.dest,
				   .ip_proto = pkt.ip_header.ip_p,
				   .flow_up = NULL,
				   .flow_down = NULL,
			   }
			 : (flow_base_t){
				   .sip = pkt.ip_header.ip_src,
				   .dip = pkt.ip_header.ip_dst,
				   .sp= pkt.udp.source,
				   .dp= pkt.udp.dest,
				   .ip_proto = pkt.ip_header.ip_p,
				   .flow_up = NULL,
				   .flow_down = NULL,
			   };
}

// get flow direction by compare src ip of the packet with the flow
Node **get_flow_direction(flow_base_t const *flow, parsed_packet pkt, FILE* stream) {
  LOG_DBG(stream, DBG_PARSER, "***%u vs %u***\n", pkt.ip_header.ip_src.s_addr, flow->sip.s_addr);
  return pkt.ip_header.ip_src.s_addr == flow->sip.s_addr 
    ? (Node **)(&flow->flow_up)
    : (Node **)(&flow->flow_down);
}

/*
 * print package payload data (avoid printing binary data)
 */
void print_payload(u_char const *payload, uint payload_size, FILE* stream) {

  /** if (payload_size > 0) { */
  /**   LOG_DBG(stream, DBG_PARSER, "\t\tpayload size: %u bytes\n", payload_size); */
  /** } 
   * else { */
  /**   LOG_DBG(stream, DBG_PARSER, "\t\tpayload size: 0 bytes\n"); */
  /**   return; */
  /** } */

  LOG_DBG(stream, DBG_PARSER, "\n");

  int len = payload_size;
  int len_rem = payload_size;
  int line_width = 11; /* number of bytes per line */
  int line_len;
  int offset = 0; /* zero-based offset counter */
  u_char const *ch = payload;

  if (len <= 0)
    return;

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

void print_hex_ascii_line(u_char const *const payload, int len, int offset, FILE* stream) {

  int gap;
  u_char const *ch;

  /* offset */
  LOG_DBG(stream, DBG_PARSER, "\t\t%05d   ", offset);

  /* hex */
  ch = payload;
  for (int i = 0; i < len; i++) {
    LOG_DBG(stream, DBG_PARSER, "%02x ", *ch);
    ch++;
    /* print extra space after 8th byte for visual aid */
    if (i == 7)
      LOG_DBG(stream, DBG_PARSER, " ");
  }
  /* print space to handle line less than 8 bytes */
  if (len < 8)
    LOG_DBG(stream, DBG_PARSER, " ");

  /* fill hex gap with spaces if not full line */
  if (len < 16) {
    gap = 16 - len;
    for (int i = 0; i < gap; i++) {
      LOG_DBG(stream, DBG_PARSER, "   ");
    }
  }
  LOG_DBG(stream, DBG_PARSER, "   ");

  /* ascii (if printable) */
  ch = payload;
  for (int i = 0; i < len; i++) {
    if (isprint(*ch)) {
      LOG_DBG(stream, DBG_PARSER, "%c", *ch);
    } 
    else {
      LOG_DBG(stream, DBG_PARSER, ".");
    }
    ch++;
  }

  LOG_DBG(stream, DBG_PARSER, "\n");

  return;
}
