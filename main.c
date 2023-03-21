#include "lib/handler.h"
#include "lib/hash_table.h"
#include <glib-2.0/glib.h>
#include <pcap.h>
#include <stdbool.h>

void get_packets(pcap_t *handler, FILE *fout_parser, FILE *fout_seq_filter,
                 FILE *fout_list_flow);

static gboolean smtp_auth_parameter_decoding_enabled = FALSE;

/*
 * See
 *
 *      http://support.microsoft.com/default.aspx?scid=kb;[LN];812455
 *
 * for the Exchange extensions.
 */
static const struct {
  const char *command;
  int len;
} commands[] = {
    {"STARTTLS", 8},      /* RFC 2487 */
    {"X-EXPS", 6},        /* Microsoft Exchange */
    {"X-LINK2STATE", 12}, /* Microsoft Exchange */
    {"XEXCH50", 7}        /* Microsoft Exchange */
};
#define NCOMMANDS (sizeof commands / sizeof commands[0])


/*
 * A CMD is an SMTP command, MESSAGE is the message portion, and EOM is the
 * last part of a message
 */
#define SMTP_PDU_CMD 0
#define SMTP_PDU_MESSAGE 1
#define SMTP_PDU_EOM 2

struct smtp_proto_data {
  guint16 pdu_type;
  guint16 conversation_id;
  gboolean more_frags;
};

/*
 * State information stored with a conversation.
 */
typedef enum {
  SMTP_STATE_START,                     /* Start of SMTP conversion */
  SMTP_STATE_READING_CMDS,              /* reading commands */
  SMTP_STATE_READING_DATA,              /* reading message data */
  SMTP_STATE_AWAITING_STARTTLS_RESPONSE /* sent STARTTLS, awaiting response */
} smtp_state_t;

typedef enum {
  SMTP_AUTH_STATE_NONE,  /*  No authentication seen or used */
  SMTP_AUTH_STATE_START, /* Authentication started, waiting for username */
  SMTP_AUTH_STATE_USERNAME_REQ,    /* Received username request from server */
  SMTP_AUTH_STATE_USERNAME_RSP,    /* Received username response from client */
  SMTP_AUTH_STATE_PASSWORD_REQ,    /* Received password request from server */
  SMTP_AUTH_STATE_PASSWORD_RSP,    /* Received password request from server */
  SMTP_AUTH_STATE_PLAIN_START_REQ, /* Received AUTH PLAIN command from client*/
  SMTP_AUTH_STATE_PLAIN_CRED_REQ, /* Received AUTH PLAIN command including creds
                                     from client*/
  SMTP_AUTH_STATE_PLAIN_REQ,      /* Received AUTH PLAIN request from server */
  SMTP_AUTH_STATE_PLAIN_RSP,      /* Received AUTH PLAIN response from client */
  SMTP_AUTH_STATE_NTLM_REQ, /* Received ntlm negotiate request from client */
  SMTP_AUTH_STATE_NTLM_CHALLANGE, /* Received ntlm challange request from server
                                   */
  SMTP_AUTH_STATE_NTLM_RSP,       /* Received ntlm auth request from client */
  SMTP_AUTH_STATE_SUCCESS, /* Password received, authentication successful,
                              start decoding */
  SMTP_AUTH_STATE_FAILED   /* authentication failed, no decoding */
} smtp_auth_state_t;

struct smtp_session_state {
  smtp_state_t smtp_state;      /* Current state */
  smtp_auth_state_t auth_state; /* Current authentication state */
  /* Values that need to be saved because state machine can't be used during
   * tree dissection */
  uint8_t *username;     /* The username in the authentication. */
  bool crlf_seen;        /* Have we seen a CRLF on the end of a packet */
  bool data_seen;        /* Have we seen a DATA command yet */
  uint32_t msg_read_len; /* Length of BDAT message read so far */
  uint32_t msg_tot_len;  /* Total length of BDAT message */
  bool msg_last;         /* Is this the last BDAT chunk */
};

static gboolean line_is_smtp_command(const guchar *command, int commandlen) {
  size_t i;

  /*
   * To quote RFC 821, "Command codes are four alphabetic
   * characters".
   *
   * However, there are some SMTP extensions that involve commands
   * longer than 4 characters and/or that contain non-alphabetic
   * characters; we treat them specially.
   *
   * XXX - should we just have a table of known commands?  Or would
   * that fail to catch some extensions we don't know about?
   */
  if (commandlen == 4 && g_ascii_isalpha(command[0]) &&
      g_ascii_isalpha(command[1]) && g_ascii_isalpha(command[2]) &&
      g_ascii_isalpha(command[3])) {
    /* standard 4-alphabetic command */
    return TRUE;
  }

  /*
   * Check the list of non-4-alphabetic commands.
   */
  for (i = 0; i < NCOMMANDS; i++) {
    if (commandlen == commands[i].len &&
        g_ascii_strncasecmp(command, commands[i].command, commands[i].len) == 0)
      return TRUE;
  }
  return FALSE;
}
int length_eol(const u_char *payload, int len, int offset,
               u_char *found_needle) {
  int i;
  for (i = offset; i < len + offset; i++) {
    if (payload[i] == '\r' || payload[i] == '\n') {
      *found_needle = payload[i];
      return i;
    }
  }
  return -1;
}

int payload_find_line_end(const u_char *tvb, const int offset, int len,
                          int *next_offset) {
  int eob_offset;
  int eol_offset;
  int linelen;
  u_char found_needle = 0;

  eob_offset = offset + len;

  /*
   * Look either for a CR or an LF.
   */
  eol_offset = length_eol(tvb, len, offset, &found_needle);
  /** printf("eol_offset: %d, len: %d\n", eol_offset, len); */
  if (eol_offset == -1) {
    /*
     * No CR or LF - line is presumably continued in next packet.
     */
    /*
     * Pretend the line runs to the end of the tvbuff.
     */
    linelen = eob_offset - offset;
    if (next_offset)
      *next_offset = eob_offset;
  } else {
    /*
     * Find the number of bytes between the starting offset
     * and the CR or LF.
     */
    linelen = eol_offset - offset;

    /*
     * Is it a CR?
     */
    if (found_needle == '\r') {
      /*
       * Yes - is it followed by an LF?
       */
      if (eol_offset + 1 >= eob_offset) {
        /*
         * Dunno - the next byte isn't in this
         * tvbuff.
         */
      } else {
        /*
         * Well, we can at least look at the next
         * byte.
         */
        if (*(tvb + eol_offset + 1) == '\n') {
          /*
           * It's an LF; skip over the CR.
           */
          eol_offset++;
        }
      }
    }

    /*
     * Return the offset of the character after the last
     * character in the line, skipping over the last character
     * in the line terminator.
     */
    if (next_offset)
      *next_offset = eol_offset + 1;
  }
  return linelen;
}

/*
 * Call strncmp after checking if enough chars left, returning 0 if
 * it returns 0 (meaning "equal") and -1 otherwise, otherwise return -1.
 */
gint tvb_strneql(const u_char *tvb, const gint offset, const gchar *str,
                 const size_t size) {
  const guint8 *ptr;

  ptr = tvb + offset;

  if (ptr) {
    int cmp = strncmp((const char *)ptr, str, size);

    /*
     * Return 0 if equal, -1 otherwise.
     */
    return (cmp == 0 ? 0 : -1);
  } else {
    /*
     * Not enough characters in the tvbuff to match the
     * string.
     */
    return -1;
  }
}
void smtp_decoder(u_char const *tvb, uint tvb_size,
                  struct smtp_session_state *session_state, gboolean request) {

  struct smtp_proto_data *spd_frame_data;
  int offset = 0;
  const guchar *line, *linep, *lineend;
  guint32 code;
  int linelen = 0;
  gint length_remaining;
  gboolean eom_seen = FALSE;
  gint next_offset;
  gint loffset = 0;
  int cmdlen;
  guint8 *decrypt = NULL;
  gsize decrypt_len = 0;
  u_char *next_tvb;
  guint8 line_code[3];

  if (tvb_size == 0) {
    return;
  }
  if (request) {

    /*
     * Create a frame data structure and attach it to the packet.
     */
    spd_frame_data = malloc(sizeof(struct smtp_proto_data));

    spd_frame_data->more_frags = TRUE;
  }

  loffset = offset;
  while (loffset < tvb_size) {
    linelen =
        payload_find_line_end(tvb, loffset, tvb_size - loffset, &next_offset);
    /** printf( */
    /**     "tvb_find_line_end: offset=%d,loffset=%d,next offset=%d,
     * linelen=%d\n", */
    /** offset, loffset, next_offset, linelen); */

    if (linelen == -1) {
      if (offset == loffset) {
        /*
         * We didn't find a line ending, and we're doing desegmentation;
         * tell the TCP dissector where the data for this message starts
         * in the data it handed us, and tell it we need more bytes
         */
        return tvb_size;
      } else {
        linelen = tvb_size - loffset;
        next_offset = loffset + linelen;
      }
    }

    /*
     * Check whether or not this packet is an end of message packet
     * We should look for CRLF.CRLF and they may be split.
     * We have to keep in mind that we may see what we want on
     * two passes through here ...
     */
    if (session_state->smtp_state == SMTP_STATE_READING_DATA) {
      /*
       * The order of these is important ... We want to avoid
       * cases where there is a CRLF at the end of a packet and a
       * .CRLF at the beginning of the same packet.
       */
      if ((session_state->crlf_seen &&
           tvb_strneql(tvb, loffset, ".\r\n", 3) == 0) ||
          tvb_strneql(tvb, loffset, "\r\n.\r\n", 5) == 0)
        eom_seen = TRUE;

      length_remaining = tvb_size - loffset;
      if (tvb_strneql(tvb, loffset + length_remaining - 2, "\r\n", 2) == 0)
        session_state->crlf_seen = TRUE;
      else
        session_state->crlf_seen = FALSE;
    }

    if (request) {

      if (session_state->smtp_state == SMTP_STATE_READING_DATA) {
        /*
         * This is message data.
         */
        if (eom_seen) { /* Seen the EOM */
          /*
           * EOM.
           * Everything that comes after it is commands.
           */
          spd_frame_data->pdu_type = SMTP_PDU_EOM;
          session_state->smtp_state = SMTP_STATE_READING_CMDS;
          break;
        } else {
          /*
           * Message data with no EOM.
           */
          spd_frame_data->pdu_type = SMTP_PDU_MESSAGE;

          if (session_state->msg_tot_len > 0) {
            /*
             * We are handling a BDAT message.
             * Check if we have reached end of the data chunk.
             */
            session_state->msg_read_len += tvb - loffset;
            /*
             * Since we're grabbing the rest of the packet, update the
             * offset accordingly
             */
            next_offset = tvb_size;

            if (session_state->msg_read_len == session_state->msg_tot_len) {
              /*
               * We have reached end of BDAT data chunk.
               * Everything that comes after this is commands.
               */
              session_state->smtp_state = SMTP_STATE_READING_CMDS;

              if (session_state->msg_last) {
                /*
                 * We have found the LAST data chunk.
                 * The message can now be reassembled.
                 */
                spd_frame_data->more_frags = FALSE;
              }

              break; /* no need to go through the remaining lines */
            }
          }
        }
      } else {
        /*
         * This is commands - unless the capture started in the
         * middle of a session, and we're in the middle of data.
         *
         * Commands are not necessarily 4 characters; look
         * for a space or the end of the line to see where
         * the putative command ends.
         */
        if ((session_state->auth_state != SMTP_AUTH_STATE_NONE)) {
          decrypt = (u_char *)g_memdup(tvb, linelen);
          if ((smtp_auth_parameter_decoding_enabled) && (strlen(decrypt) > 1) &&
              (g_base64_decode_inplace(decrypt, &decrypt_len)) &&
              (decrypt_len > 0)) {
            decrypt[decrypt_len] = 0;
            line = decrypt;
            linelen = (int)decrypt_len;
          } else {
            line = tvb;
            decrypt_len = linelen;
          }
        } else {
          line = tvb;
        }

        /** line = tvb; */

        linep = line;
        lineend = line + linelen;
        while (linep < lineend && *linep != ' ')
          linep++;
        cmdlen = (int)(linep - line);
        if (line_is_smtp_command(line, cmdlen)) {
          if (g_ascii_strncasecmp(line, "DATA", 4) == 0) {
            /*
             * DATA command.
             * This is a command, but everything that comes after it,
             * until an EOM, is data.
             */
            spd_frame_data->pdu_type = SMTP_PDU_CMD;
            session_state->smtp_state = SMTP_STATE_READING_DATA;
            session_state->data_seen = TRUE;
            printf("DATA command seen\n");
          } else if (g_ascii_strncasecmp(line, "BDAT", 4) == 0) {
            /*
             * BDAT command.
             * This is a command, but everything that comes after it,
             * until given length is received, is data.
             */
            guint32 msg_len;

            msg_len = (guint32)strtoul(line + 5, NULL, 10);

            spd_frame_data->pdu_type = SMTP_PDU_CMD;
            session_state->data_seen = TRUE;
            session_state->msg_tot_len += msg_len;

            if (msg_len == 0) {
              /* No data to read, next will be a command */
              session_state->smtp_state = SMTP_STATE_READING_CMDS;
            } else {
              session_state->smtp_state = SMTP_STATE_READING_DATA;
            }

            if (g_ascii_strncasecmp(line + linelen - 4, "LAST", 4) == 0) {
              /*
               * This is the last data chunk.
               */
              session_state->msg_last = TRUE;

              if (msg_len == 0) {
                /*
                 * No more data to expect.
                 * The message can now be reassembled.
                 */
                spd_frame_data->more_frags = FALSE;
              }
            } else {
              session_state->msg_last = FALSE;
            }
          } else if ((g_ascii_strncasecmp(line, "AUTH LOGIN", 10) == 0) &&
                     (linelen <= 11)) {
            /*
             * AUTH LOGIN command.
             * Username is in a separate frame
             */
            spd_frame_data->pdu_type = SMTP_PDU_CMD;
            session_state->smtp_state = SMTP_STATE_READING_CMDS;
            session_state->auth_state = SMTP_AUTH_STATE_START;
            printf("AUTH LOGIN command seen\n");
          } else if ((g_ascii_strncasecmp(line, "AUTH LOGIN", 10) == 0) &&
                     (linelen > 11)) {
            /*
             * AUTH LOGIN command.
             * Username follows the 'AUTH LOGIN' string
             */
            spd_frame_data->pdu_type = SMTP_PDU_CMD;
            session_state->smtp_state = SMTP_STATE_READING_CMDS;
            session_state->auth_state = SMTP_AUTH_STATE_USERNAME_RSP;
          } else {
            /*
             * Regular command.
             */
          }
        } else if (session_state->auth_state == SMTP_AUTH_STATE_USERNAME_REQ) {
          session_state->auth_state = SMTP_AUTH_STATE_USERNAME_RSP;
        } else if (session_state->auth_state == SMTP_AUTH_STATE_PASSWORD_REQ) {
          session_state->auth_state = SMTP_AUTH_STATE_PASSWORD_RSP;
        } else if (session_state->auth_state == SMTP_AUTH_STATE_PLAIN_REQ) {
          session_state->auth_state = SMTP_AUTH_STATE_PLAIN_RSP;
        } else if (session_state->auth_state ==
                   SMTP_AUTH_STATE_NTLM_CHALLANGE) {
          session_state->auth_state = SMTP_AUTH_STATE_NTLM_RSP;
        } else {

          /*
           * Assume it's message data.
           */
          spd_frame_data->pdu_type =
              (session_state->data_seen ||
               (session_state->smtp_state == SMTP_STATE_START))
                  ? SMTP_PDU_MESSAGE
                  : SMTP_PDU_CMD;
        }
      }

      /*
       * Step past this line.
       */
      loffset = next_offset;
    }
  }
  printf("payload: %s\n", tvb);
}

void flow_browser(flow_base_t *flow) {

  if (flow == NULL) {
    printf("ERROR: flow is null\n");
    return;
  }
  struct smtp_session_state session_state = {.smtp_state = SMTP_STATE_START,
                                             .auth_state = SMTP_AUTH_STATE_NONE,
                                             .msg_last = true};

  Node const *temp = flow->head_flow;

  while (temp != NULL) {

	smtp_decoder(((parsed_payload *)temp->value)->data,
                 ((parsed_payload *)temp->value)->data_len, &session_state,
				 true);

    printf("payload size: %d\n", ((parsed_payload *)temp->value)->data_len);
    temp = temp->next;
  }
}

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

void get_packets(pcap_t *handler, FILE *fout_parser, FILE *fout_seq_filter,
                 FILE *fout_list_flow) {

  // The header that pcap gives us
  struct pcap_pkthdr *header_pcap;

  // The actual packet
  u_char const *full_packet;

  uint32_t packet_count = 0;

  // create hash table
  HashTable table = create_hash_table(HASH_TABLE_SIZE);

  while (pcap_next_ex(handler, &header_pcap, &full_packet) >= 0) {

    packet_count++;

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

    LOG_DBG(fout_parser, DBG_PARSER,
            "----------------------------------------"
            "-----------Successfully---------------\n");
    // LOG_DBG(OUTPUT_4, 0, "***After packet %u: %u packets.\n", packet_count,
    // count_packets(table));
    if (packet_count > LIMIT_PACKET)
      break;
    continue;

  END : {
    LOG_DBG(fout_parser, DBG_PARSER,
            "----------------------------------------"
            "---------PacketFailed-----------------\n");
    if (packet_count > LIMIT_PACKET)
      break;
  }
  }

  print_hashtable(table, fout_list_flow);

  flow_browser(search_flow(table, 6813568831684183325, stdout));

  LOG_DBG(fout_parser, 1, "Program run successfully");
  printf("Freeing...\n");
  // free_hash_table(table);
}
