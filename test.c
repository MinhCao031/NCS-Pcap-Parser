#include "lib/handler.h"

#include "lib/dissect_smtp.h"
#include "lib/ws/wsutil/str_util.h"
#include "lib/ws/wsutil/ws_assert.h"

#include <string.h>
#include <sys/types.h>

#define PNAME "Internet Message Format"
#define PSNAME "IMF"
#define PFNAME "imf"

#define NO_SUBDISSECTION NULL

typedef struct _value_string {
  const char *strptr;
  guint32 value;
} value_string;

enum field {
  IMF_FIELD_FROM,
  IMF_FIELD_TO,
  IMF_FIELD_CC,
  IMF_FIELD_BCC,
  IMF_FIELD_REPLY_TO,
  IMF_FIELD_SENDER,
  IMF_FIELD_RESENT_FROM,
  IMF_FIELD_RESENT_TO,
  IMF_FIELD_RESENT_CC,
  IMF_FIELD_RESENT_BCC,
  IMF_FIELD_RESENT_REPLY_TO,
  IMF_FIELD_RESENT_SENDER,
  IMF_FIELD_RESENT_MESSAGE_ID,
  IMF_FIELD_MESSAGE_ID,
  IMF_FIELD_IN_REPLY_TO,
  IMF_FIELD_REFERENCES,
  IMF_FIELD_SUBJECT,
  IMF_FIELD_COMMENTS,
  IMF_FIELD_KEYWORDS,
  IMF_FIELD_ERRORS_TO,
  IMF_FIELD_CONTENT_TYPE
};

struct imf_field {
  const char *name;
  enum field hf_id;
  void (*dissect)();
};

static void dissect_imf_mailbox();
static void dissect_imf_address();
static void dissect_imf_address_list();
static void dissect_imf_mailbox_list();
static void dissect_imf_siolabel();

const struct imf_field imf_fields[] = {

    {"from", IMF_FIELD_FROM, dissect_imf_mailbox_list},
    {"to", IMF_FIELD_TO, dissect_imf_address_list},
    {"cc", IMF_FIELD_CC, dissect_imf_address_list},
    {"bcc", IMF_FIELD_BCC, dissect_imf_address_list},
    {"reply-to", IMF_FIELD_REPLY_TO, dissect_imf_address_list},
    {"sender", IMF_FIELD_SENDER, dissect_imf_mailbox},
    {"resent-from", IMF_FIELD_RESENT_FROM, dissect_imf_mailbox_list},
    {"resent-to", IMF_FIELD_RESENT_TO, dissect_imf_address_list},
    {"resent-cc", IMF_FIELD_RESENT_CC, dissect_imf_address_list},
    {"resent-bcc", IMF_FIELD_RESENT_BCC, dissect_imf_address_list},
    {"resent-reply-to", IMF_FIELD_RESENT_REPLY_TO, dissect_imf_address_list},
    {"resent-sender", IMF_FIELD_RESENT_SENDER, dissect_imf_mailbox},
    {"resent-message-id", IMF_FIELD_RESENT_MESSAGE_ID, dissect_imf_siolabel},
    {"message-id", IMF_FIELD_MESSAGE_ID, dissect_imf_siolabel},
    {"in-reply-to", IMF_FIELD_IN_REPLY_TO, dissect_imf_siolabel},
    {"references", IMF_FIELD_REFERENCES, dissect_imf_siolabel},
    {"subject", IMF_FIELD_SUBJECT, NO_SUBDISSECTION},
    {"comments", IMF_FIELD_COMMENTS, NO_SUBDISSECTION},
    {"keywords", IMF_FIELD_KEYWORDS, NO_SUBDISSECTION},
    {"errors-to", IMF_FIELD_ERRORS_TO, dissect_imf_address},
    {"content-type", IMF_FIELD_CONTENT_TYPE, NO_SUBDISSECTION},
    {NULL, 0, NULL}};

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

int imf_find_field_end(const u_char *tvb, int offset, gint max_length,
                       gboolean *last_field) {

  while (offset < max_length) {

    /* look for CR */
    offset = tvb_find_char(tvb, offset, max_length - offset, '\r');

    if (offset != -1) {
      /* protect against buffer overrun and only then look for next char */
      if (++offset < max_length && *(tvb + offset) == '\n') {
        /* OK - so we have found CRLF */
        if (++offset >= max_length) {
          /* end of buffer and also end of fields */
          if (last_field) {
            *last_field = TRUE;
          }
          /* caller expects that there is CRLF after returned offset, if
           * last_field is set */
          return offset - 2;
        }
        /* peek the next character */
        switch (*(tvb + offset)) {
        case '\r':
          /* probably end of the fields */
          if ((offset + 1) < max_length && *(tvb + offset + 1) == '\n') {
            if (last_field) {
              *last_field = TRUE;
            }
          }
          return offset;
        case ' ':
        case '\t':
          /* continuation line */
          break;
        default:
          /* this is a new field */
          return offset;
        }
      }
    } else {
      /* couldn't find a CR - strange */
      break;
    }
  }

  return -1; /* Fail: No CR found (other than possible continuation) */
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

    if (end_offset == -1) {
      // no colon found, so this is not a valid header
      break;
    } else {
      key = g_strndup((const char *)tvb + start_offset,
                      end_offset - start_offset);

      // convert to lower case
      key = g_ascii_strdown(key, end_offset - start_offset);

      // find imf_field from imf_fields array
      // for(f_info = imf_fields; f_info->name; f_info++) {
      //   if (strcmp(f_info->name, key) == 0) {
      //     break;
      //   }
      // }

      // printf("F info Key: %s, id: %d\n", key, f_info->hf_id);

      /* value starts immediately after the colon */
      start_offset = end_offset + 1;

      end_offset =
          imf_find_field_end(tvb, start_offset, max_length, &last_field);
    }

    /* remove any leading whitespace */
    for (value_offset = start_offset; value_offset < end_offset; value_offset++)
      if (!g_ascii_isspace(*(tvb + value_offset))) {
        break;
      }
    // printf("Key: %s\n", key);
    // // print value with start_offset and end_offset
    // printf("Value: %.*s", end_offset - start_offset,
    //        (const char *)tvb + start_offset);

    // print key-value pair in pretty table format
    printf("%-30s %.*s", key, end_offset - start_offset,
           (const char *)tvb + start_offset);

    start_offset = end_offset;
  }

  if (last_field) {
    end_offset += 2;
  }

  next_tvb = (u_char *)tvb + end_offset;
  // print next tvb
  // printf("Next tvb: %s", next_tvb);
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

  print_hashtable(table, fout_list_flow);

  flow_base_t *flow_test = search_flow(table, 6813568831684183325, stdout);
  flow_browser(flow_test);

  printf("\nFreeing...\n");
  free_hash_table(table);
}
