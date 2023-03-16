#pragma GCC diagnostic ignored "-Wunused-parameter"

#include "lib/handler.h"
#include "lib/log.h"
#include "lib/parsers.h"
#include <assert.h>
#include <pcap.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>

#include <glib.h>

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
  uint32_t first_auth_frame;   /* First frame involving authentication. */
  uint32_t username_frame;     /* Frame containing client username */
  uint32_t password_frame;     /* Frame containing client password */
  uint32_t last_auth_frame;    /* Last frame involving authentication. */
  uint8_t *username;           /* The username in the authentication. */
  bool crlf_seen;              /* Have we seen a CRLF on the end of a packet */
  bool data_seen;              /* Have we seen a DATA command yet */
  uint32_t msg_read_len;       /* Length of BDAT message read so far */
  uint32_t msg_tot_len;        /* Total length of BDAT message */
  bool msg_last;               /* Is this the last BDAT chunk */
  uint32_t username_cmd_frame; /* AUTH command contains username */
  uint32_t
      user_pass_cmd_frame;  /* AUTH command contains username and password */
  uint32_t user_pass_frame; /* Frame contains username and password */
  uint32_t ntlm_req_frame;  /* Frame containing NTLM request */
  uint32_t ntlm_cha_frame;  /* Frame containing NTLM challange. */
  uint32_t ntlm_rsp_frame;  /* Frame containing NTLM response. */
};

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
  printf("eol_offset: %d, len: %d\n", eol_offset, len);
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
                  struct smtp_session_state *session_state) {

  int                        offset    = 0;
  int                        request   = 0;
  const guchar              *line, *linep, *lineend;
  guint32                    code;
  int                        linelen   = 0;
  gint                       length_remaining;
  gboolean                   eom_seen  = FALSE;
  gint                       next_offset;
  gint                       loffset   = 0;
  int                        cmdlen;
  u_char *next_tvb;
  guint8                     line_code[3];

  if (tvb_size == 0) {
    return;
  }

  printf("payload: %s\n", tvb);

  while (loffset < tvb_size) {
    linelen =
        payload_find_line_end(tvb, loffset, tvb_size - loffset, &next_offset);
    printf(
        "tvb_find_line_end: offset=%d,loffset=%d,next offset=%d, linelen=%d\n",
        offset, loffset, next_offset, linelen);

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

    loffset = next_offset;
  }
}

void direction_browser(Node const *head, bool is_up,
                       struct smtp_session_state *session_state) {

  Node const *temp = head;

  while (temp != NULL) {

    smtp_decoder(((parsed_payload *)temp->value)->data,
                 ((parsed_payload *)temp->value)->data_len, session_state);

    temp = temp->next;
  }
}

void flow_browser(flow_base_t flow) {

  struct smtp_session_state session_state = {.smtp_state = SMTP_STATE_START,
                                             .auth_state = SMTP_AUTH_STATE_NONE,
                                             .msg_last = true};

  direction_browser(flow.flow_up, true, &session_state);
  direction_browser(flow.flow_down, false, &session_state);
}

void get_mail_address(char *address, u_char const *payload, uint payload_size) {

  uint start, end;

  for (uint i = 0; i < payload_size; i++) {
    if (payload[i] == '<') {
      start = i + 1;
    }

    if (payload[i] == '>') {
      end = i;
    }
  }

  int length = end - start;

  for (int i = 0; i < length; i++) {
    address[i] = payload[start + i];
  }

  address[length] = '\0';
}

void get_packets(pcap_t *handler, FILE *fout_parser, FILE *fout_seq_filter,
                 FILE *fout_list_flow) {

  // The header that pcap gives us
  struct pcap_pkthdr *header_pcap;

  // The actual packet
  u_char const *full_packet;

  int packetCount = 0;

  // create List of flow_stream
  Node *temp = create_dumb_node(fout_list_flow);
  Node *headlist = temp;

  while (pcap_next_ex(handler, &header_pcap, &full_packet) >= 0) {

    // Show the packet number & timestamp
    char full_timestamp[80];
    struct tm ts = *localtime(&((header_pcap->ts).tv_sec));
    strftime(full_timestamp, sizeof(full_timestamp), "%a %Y-%m-%d %H:%M:%S %Z",
             &ts);

    LOG_DBG(
        fout_parser, DBG_PARSER,
        "Packet # %i\nTime in sec & microsec: %lu.%6lu\nFull timestamp = %s\n",
        ++packetCount, (header_pcap->ts).tv_sec, (header_pcap->ts).tv_usec,
        full_timestamp);
    LOG_SCR("Packet # %i\n", packetCount);

    // Dissection Step 1 of
    // 4----------------------------------------------------------------------
    package frame = frame_dissector(full_packet, header_pcap, fout_parser);
    if (frame.is_valid == false) {
      LOG_DBG(fout_parser, DBG_PARSER, "ERROR: Frame is not valid!\n");
      goto END;
    }

    // Dissection Step 2 of
    // 4----------------------------------------------------------------------
    package packet = link_dissector(frame, fout_parser);
    if (packet.is_valid == false) {
      LOG_DBG(fout_parser, DBG_PARSER, "ERROR: Packet is not valid!\n");
      goto END;
    }

    // Dissection Step 3 of
    // 4----------------------------------------------------------------------
    package segment = network_dissector(packet, fout_parser);
    if (segment.is_valid == false) {
      LOG_DBG(fout_parser, DBG_PARSER, "ERROR: Segment is not valid!\n");
      goto END;
    }

    // Dissection Step 4 of
    // 4----------------------------------------------------------------------
    package payload = transport_demux(segment, fout_parser);
    if (payload.is_valid == false) {
      LOG_DBG(fout_parser, DBG_PARSER, "ERROR: Payload is not valid!\n");
      goto END;
    }

    // Store packets in the list
    parsed_packet pkt = pkt_parser(packet, segment, payload);
    insert_packet(&headlist, pkt, fout_parser);
    LOG_DBG(fout_parser, DBG_PARSER,
            "-------------------------------------"
            "-----------Successfully------------\n");
    if (packetCount > LIMIT_PACKET)
      break;
    continue;

  END : {
    LOG_DBG(fout_parser, DBG_PARSER,
            "-------------------------------------"
            "---------PacketFailed--------------\n");
    if (packetCount > LIMIT_PACKET)
      break;
  }
  }

  review_flowlist(&headlist, fout_seq_filter);

  flow_browser(*search_flow(&headlist, 2392258525328658816, stdout));

  free_flow_list(&headlist);
}
int main(void) {
  // error buffer
  char errbuff[PCAP_ERRBUF_SIZE];

  // open file and create pcap handler
  pcap_t *const handler = pcap_open_offline(PCAP_FILE, errbuff);
  if (handler == NULL) {
    LOG_DBG(OUTPUT_E, DBG_ERROR, "Error opening file: %s\n", errbuff);
    exit(EXIT_FAILURE);
  }

  get_packets(handler, OUTPUT_1, OUTPUT_2, OUTPUT_3);

  pcap_close(handler);
  fclose(OUTPUT_1);
  fclose(OUTPUT_2);
  fclose(OUTPUT_3);
  fclose(OUTPUT_E);
  return 0;
}
