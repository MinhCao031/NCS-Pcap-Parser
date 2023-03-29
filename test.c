#include "lib/handler.h"

#include "lib/dissect_smtp.h"
#include "lib/ws/wsutil/str_util.h"

#include <string.h>

#define PNAME "Internet Message Format"
#define PSNAME "IMF"
#define PFNAME "imf"

static int proto_imf = -1;

static int hf_imf_date = -1;
static int hf_imf_from = -1;
static int hf_imf_sender = -1;
static int hf_imf_reply_to = -1;
static int hf_imf_to = -1;
static int hf_imf_cc = -1;
static int hf_imf_bcc = -1;
static int hf_imf_message_id = -1;
static int hf_imf_in_reply_to = -1;
static int hf_imf_references = -1;
static int hf_imf_subject = -1;
static int hf_imf_comments = -1;
static int hf_imf_user_agent = -1;
static int hf_imf_keywords = -1;
static int hf_imf_resent_date = -1;
static int hf_imf_resent_from = -1;
static int hf_imf_resent_sender = -1;
static int hf_imf_resent_to = -1;
static int hf_imf_resent_cc = -1;
static int hf_imf_resent_bcc = -1;
static int hf_imf_resent_message_id = -1;
static int hf_imf_return_path = -1;
static int hf_imf_received = -1;
static int hf_imf_content_type = -1;
static int hf_imf_content_type_type = -1;
static int hf_imf_content_type_parameters = -1;
static int hf_imf_content_id = -1;
static int hf_imf_content_transfer_encoding = -1;
static int hf_imf_content_description = -1;
static int hf_imf_mime_version = -1;
static int hf_imf_thread_index = -1;
static int hf_imf_ext_mailer = -1;
static int hf_imf_ext_mimeole = -1;
static int hf_imf_ext_tnef_correlator = -1;
static int hf_imf_ext_expiry_date = -1;
static int hf_imf_ext_uidl = -1;
static int hf_imf_ext_authentication_warning = -1;
static int hf_imf_ext_virus_scanned = -1;
static int hf_imf_extension = -1;
static int hf_imf_extension_type = -1;
static int hf_imf_extension_value = -1;

/* RFC 2156 */
static int hf_imf_autoforwarded = -1;
static int hf_imf_autosubmitted = -1;
static int hf_imf_x400_content_identifier = -1;
static int hf_imf_content_language = -1;
static int hf_imf_conversion = -1;
static int hf_imf_conversion_with_loss = -1;
static int hf_imf_delivery_date = -1;
static int hf_imf_discarded_x400_ipms_extensions = -1;
static int hf_imf_discarded_x400_mts_extensions = -1;
static int hf_imf_dl_expansion_history = -1;
static int hf_imf_deferred_delivery = -1;
static int hf_imf_expires = -1;
static int hf_imf_importance = -1;
static int hf_imf_incomplete_copy = -1;
static int hf_imf_latest_delivery_time = -1;
static int hf_imf_message_type = -1;
static int hf_imf_original_encoded_information_types = -1;
static int hf_imf_originator_return_address = -1;
static int hf_imf_priority = -1;
static int hf_imf_reply_by = -1;
static int hf_imf_sensitivity = -1;
static int hf_imf_supersedes = -1;
static int hf_imf_x400_content_type = -1;
static int hf_imf_x400_mts_identifier = -1;
static int hf_imf_x400_originator = -1;
static int hf_imf_x400_received = -1;
static int hf_imf_x400_recipients = -1;

static int hf_imf_delivered_to = -1;

static int hf_imf_message_text = -1;

static int hf_imf_display_name = -1;
static int hf_imf_address = -1;
/* static int hf_imf_mailbox_list = -1; */
static int hf_imf_mailbox_list_item = -1;
/* static int hf_imf_address_list = -1; */
static int hf_imf_address_list_item = -1;

/* draft-zeilenga-email-seclabel-04 */
static int hf_imf_siolabel = -1;
static int hf_imf_siolabel_marking = -1;
static int hf_imf_siolabel_fgcolor = -1;
static int hf_imf_siolabel_bgcolor = -1;
static int hf_imf_siolabel_type = -1;
static int hf_imf_siolabel_label = -1;
static int hf_imf_siolabel_unknown = -1;

static int ett_imf = -1;
static int ett_imf_content_type = -1;
static int ett_imf_mailbox = -1;
static int ett_imf_group = -1;
static int ett_imf_mailbox_list = -1;
static int ett_imf_address_list = -1;
static int ett_imf_siolabel = -1;
static int ett_imf_extension = -1;
static int ett_imf_message_text = -1;

#define NO_SUBDISSECTION NULL

struct imf_field {
  char *name; /* field name - in lower case for matching purposes */
  int *hf_id; /* wireshark field */
  void (*subdissector)();
  gboolean add_to_col_info; /* add field to column info */
};
static void dissect_imf_mailbox();
static void dissect_imf_address();
static void dissect_imf_address_list();
static void dissect_imf_mailbox_list();
static void dissect_imf_siolabel();

static struct imf_field imf_fields[] = {
    {"unknown-extension", &hf_imf_extension_type, NO_SUBDISSECTION,
     FALSE},                                         /* unknown extension */
    {"date", &hf_imf_date, NO_SUBDISSECTION, FALSE}, /* date-time */
    {"from", &hf_imf_from, dissect_imf_mailbox_list, TRUE}, /* mailbox_list */
    {"sender", &hf_imf_sender, dissect_imf_mailbox, FALSE}, /* mailbox */
    {"reply-to", &hf_imf_reply_to, dissect_imf_address_list,
     FALSE},                                               /* address_list */
    {"to", &hf_imf_to, dissect_imf_address_list, FALSE},   /* address_list */
    {"cc", &hf_imf_cc, dissect_imf_address_list, FALSE},   /* address_list */
    {"bcc", &hf_imf_bcc, dissect_imf_address_list, FALSE}, /* address_list */
    {"message-id", &hf_imf_message_id, NO_SUBDISSECTION, FALSE},   /* msg-id */
    {"in-reply-to", &hf_imf_in_reply_to, NO_SUBDISSECTION, FALSE}, /* msg-id */
    {"references", &hf_imf_references, NO_SUBDISSECTION, FALSE},   /* msg-id */
    {"subject", &hf_imf_subject, NO_SUBDISSECTION, TRUE},    /* unstructured */
    {"comments", &hf_imf_comments, NO_SUBDISSECTION, FALSE}, /* unstructured */
    {"user-agent", &hf_imf_user_agent, NO_SUBDISSECTION,
     FALSE},                                     /* unstructured */
    {"keywords", &hf_imf_keywords, NULL, FALSE}, /* phrase_list */
    {"resent-date", &hf_imf_resent_date, NO_SUBDISSECTION, FALSE},
    {"resent-from", &hf_imf_resent_from, dissect_imf_mailbox_list, FALSE},
    {"resent-sender", &hf_imf_resent_sender, dissect_imf_mailbox, FALSE},
    {"resent-to", &hf_imf_resent_to, dissect_imf_address_list, FALSE},
    {"resent-cc", &hf_imf_resent_cc, dissect_imf_address_list, FALSE},
    {"resent-bcc", &hf_imf_resent_bcc, dissect_imf_address_list, FALSE},
    {"resent-message-id", &hf_imf_resent_message_id, NO_SUBDISSECTION, FALSE},
    {"return-path", &hf_imf_return_path, NULL, FALSE},
    {"received", &hf_imf_received, NO_SUBDISSECTION, FALSE},
    /* these are really multi-part - but we parse them anyway */
    {"content-type", &hf_imf_content_type, NULL,
     FALSE}, /* handled separately as a special case */
    {"content-id", &hf_imf_content_id, NULL, FALSE},
    {"content-description", &hf_imf_content_description, NULL, FALSE},
    {"content-transfer-encoding", &hf_imf_content_transfer_encoding, NULL,
     FALSE},
    {"mime-version", &hf_imf_mime_version, NO_SUBDISSECTION, FALSE},
    /* MIXER - RFC 2156 */
    {"autoforwarded", &hf_imf_autoforwarded, NULL, FALSE},
    {"autosubmitted", &hf_imf_autosubmitted, NULL, FALSE},
    {"x400-content-identifier", &hf_imf_x400_content_identifier, NULL, FALSE},
    {"content-language", &hf_imf_content_language, NULL, FALSE},
    {"conversion", &hf_imf_conversion, NULL, FALSE},
    {"conversion-with-loss", &hf_imf_conversion_with_loss, NULL, FALSE},
    {"delivery-date", &hf_imf_delivery_date, NULL, FALSE},
    {"discarded-x400-ipms-extensions", &hf_imf_discarded_x400_ipms_extensions,
     NULL, FALSE},
    {"discarded-x400-mts-extensions", &hf_imf_discarded_x400_mts_extensions,
     NULL, FALSE},
    {"dl-expansion-history", &hf_imf_dl_expansion_history, NULL, FALSE},
    {"deferred-delivery", &hf_imf_deferred_delivery, NULL, FALSE},
    {"expires", &hf_imf_expires, NULL, FALSE},
    {"importance", &hf_imf_importance, NULL, FALSE},
    {"incomplete-copy", &hf_imf_incomplete_copy, NULL, FALSE},
    {"latest-delivery-time", &hf_imf_latest_delivery_time, NULL, FALSE},
    {"message-type", &hf_imf_message_type, NULL, FALSE},
    {"original-encoded-information-types",
     &hf_imf_original_encoded_information_types, NULL, FALSE},
    {"originator-return-address", &hf_imf_originator_return_address, NULL,
     FALSE},
    {"priority", &hf_imf_priority, NULL, FALSE},
    {"reply-by", &hf_imf_reply_by, NULL, FALSE},
    {"sensitivity", &hf_imf_sensitivity, NULL, FALSE},
    {"supersedes", &hf_imf_supersedes, NULL, FALSE},
    {"x400-content-type", &hf_imf_x400_content_type, NULL, FALSE},
    {"x400-mts-identifier", &hf_imf_x400_mts_identifier, NULL, FALSE},
    {"x400-originator", &hf_imf_x400_originator, NULL, FALSE},
    {"x400-received", &hf_imf_x400_received, NULL, FALSE},
    {"x400-recipients", &hf_imf_x400_recipients, NULL, FALSE},
    /* delivery */
    {"delivered-to", &hf_imf_delivered_to, dissect_imf_mailbox,
     FALSE}, /* mailbox */
    /* some others */
    {"x-mailer", &hf_imf_ext_mailer, NO_SUBDISSECTION,
     FALSE}, /* unstructured */
    {"thread-index", &hf_imf_thread_index, NO_SUBDISSECTION,
     FALSE}, /* unstructured */
    {"x-mimeole", &hf_imf_ext_mimeole, NO_SUBDISSECTION,
     FALSE}, /* unstructured */
    {"expiry-date", &hf_imf_ext_expiry_date, NO_SUBDISSECTION,
     FALSE}, /* unstructured */
    {"x-ms-tnef-correlator", &hf_imf_ext_tnef_correlator, NO_SUBDISSECTION,
     FALSE},                                               /* unstructured */
    {"x-uidl", &hf_imf_ext_uidl, NO_SUBDISSECTION, FALSE}, /* unstructured */
    {"x-authentication-warning", &hf_imf_ext_authentication_warning,
     NO_SUBDISSECTION, FALSE}, /* unstructured */
    {"x-virus-scanned", &hf_imf_ext_virus_scanned, NO_SUBDISSECTION,
     FALSE}, /* unstructured */
    {"sio-label", &hf_imf_siolabel, dissect_imf_siolabel,
     FALSE}, /* sio-label */
    {NULL, NULL, NULL, FALSE},
};

static void dissect_imf_mailbox(){};
static void dissect_imf_address(){};
static void dissect_imf_address_list(){};
static void dissect_imf_mailbox_list(){};
static void dissect_imf_siolabel(){};

// find index if charactor in string
static int tvb_find_char(const u_char *tvb, int start_offset, int max_length,
                         char c) {
  int i;
  for (i = start_offset; i < max_length; i++) {
    if (tvb[i] == c) {
      return i;
    }
  }
  return -1;
}

void dissect_imf(const u_char *tvb, size_t tvb_len) {
  const guint8 *content_type_str = NULL;
  char *content_encoding_str = NULL;
  const guint8 *parameters = NULL;
  int hf_id;
  gint start_offset = 0;
  gint value_offset = 0;
  gint unknown_offset = 0;
  gint end_offset = 0;
  gint max_length;
  gchar *key;
  gboolean last_field = FALSE;
  u_char *next_tvb;
  struct imf_field *f_info;

  max_length = tvb_len;

  while (!last_field) {

    // look for a colon first
    end_offset = tvb_find_char(tvb, start_offset, max_length, ':');
    printf("end_offset: %d\n", end_offset);

    if (end_offset == -1) {
      // no colon found, so this is not a valid header
      break;
    } else {
      key = g_strndup((const char *)tvb + start_offset,
                      end_offset - start_offset);

      
      // convert to lower case
      ascii_strdown_inplace(key);
        
    }

    printf("Key: %s\n", key);

    last_field = TRUE;
    start_offset = end_offset;
  }
}
void flow_browser(flow_base_t *flow) {

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
    // printf("User: %s\n", smtp_info->username);
    // printf("Password: %s\n", smtp_info->password);
    // printf("Num Fragments: %d\n", smtp_info->num_fragments);
    // printf("Content length: %ld\n", smtp_info->defragment_size);
    // printf("Fragments:\n");

    // // print all fragments in smtp_info->fragments, note that this is GSList
    // for (GSList *temp = smtp_info->fragments; temp != NULL; temp =
    // temp->next) {
    //   printf("%s\n", (char *)temp->data);
    // }

    // merge all fragments in smtp_info->fragments to one string
    defragment = g_malloc(smtp_info->defragment_size + 1);
    size_t offset = 0;
    for (GSList *temp = smtp_info->fragments; temp != NULL; temp = temp->next) {
      memcpy(defragment + offset, temp->data, strlen(temp->data));
      offset += strlen(temp->data);
    }
    defragment[smtp_info->defragment_size] = '\0';

    // print defragment
    // printf("%s\n", defragment);
  }

  dissect_imf(defragment, smtp_info->defragment_size);
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

  flow_base_t *flow_test = search_flow(table, 6813568831684183325, stdout);
  flow_browser(flow_test);

  printf("\nFreeing...\n");
  free_hash_table(table);
}
