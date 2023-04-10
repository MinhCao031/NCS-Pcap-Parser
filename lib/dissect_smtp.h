#ifndef DISSECT_SMTP_H
#define DISSECT_SMTP_H

#include <glib-2.0/glib.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

static gboolean smtp_auth_parameter_decoding_enabled = FALSE;

// struct store smtp info
typedef struct {

  guint8 *username;
  guint8 *password;
  guint8 *from;
  guint8 *to;
  guint8 *subject;
  guint8 num_fragments;
  GSList *fragments;
  size_t defragment_size;

} Parsed_smtp;

typedef struct _value_string {
  guint32 value;
  const gchar *strptr;
} value_string;

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

typedef enum {
  SMTP_MULTILINE_NONE,
  SMTP_MULTILINE_START,
  SMTP_MULTILINE_CONTINUE,
  SMTP_MULTILINE_END

} smtp_multiline_state_t;

static const value_string smtp_response_codes[] = {
    {211, "System status, or system help reply"},
    {214, "Help message"},
    {220, "Service ready"},
    {221, "Service closing transmission channel"},
    {235, "Authentication successful"},
    {250, "Requested mail action okay, completed"},
    {251, "User not local; will forward to <forward-path>"},
    {252, "Cannot VRFY user, but will accept message and attempt delivery"},
    {334, "Authentication challenge"},
    {354, "Start mail input; end with <CRLF>.<CRLF>"},
    {421, "Service not available, closing transmission channel"},
    {450, "Requested mail action not taken: mailbox unavailable"},
    {451, "Requested action aborted: local error in processing"},
    {452, "Requested action not taken: insufficient system storage"},
    {500, "Syntax error, command unrecognized"},
    {501, "Syntax error in parameters or arguments"},
    {502, "Command not implemented"},
    {503, "Bad sequence of commands"},
    {504, "Command parameter not implemented"},
    {530, "Authentication required"},
    {535, "Authentication credentials invalid"},
    {550, "Requested action not taken: mailbox unavailable"},
    {551, "User not local; please try <forward-path>"},
    {552, "Requested mail action aborted: exceeded storage allocation"},
    {553, "Requested action not taken: mailbox name not allowed"},
    {554, "Transaction failed"},
    {0, NULL}};
static const value_string smtp_auth_state_vals[] = {
    {SMTP_AUTH_STATE_NONE, "None"},
    {SMTP_AUTH_STATE_START, "Start"},
    {SMTP_AUTH_STATE_USERNAME_REQ, "Username Request"},
    {SMTP_AUTH_STATE_USERNAME_RSP, "Username Response"},
    {SMTP_AUTH_STATE_PASSWORD_REQ, "Password Request"},
    {SMTP_AUTH_STATE_PASSWORD_RSP, "Password Response"},
    {SMTP_AUTH_STATE_PLAIN_START_REQ, "Plain Start Request"},
    {SMTP_AUTH_STATE_PLAIN_CRED_REQ, "Plain Credentials Request"},
    {SMTP_AUTH_STATE_PLAIN_REQ, "Plain Request"},
    {SMTP_AUTH_STATE_PLAIN_RSP, "Plain Response"},
    {SMTP_AUTH_STATE_NTLM_REQ, "NTLM Request"},
    {SMTP_AUTH_STATE_NTLM_CHALLANGE, "NTLM Challange"},
    {SMTP_AUTH_STATE_NTLM_RSP, "NTLM Response"},
    {SMTP_AUTH_STATE_SUCCESS, "Success"},
    {SMTP_AUTH_STATE_FAILED, "Failed"},
    {0, NULL}};

static const value_string smtp_state_vals[] = {
    {SMTP_STATE_START, "Start"},
    {SMTP_STATE_READING_CMDS, "Reading Commands"},
    {SMTP_STATE_READING_DATA, "Reading Data"},
    {SMTP_STATE_AWAITING_STARTTLS_RESPONSE, "Awaiting STARTTLS Response"},
    {0, NULL}};

struct smtp_session_state {
  smtp_state_t smtp_state;      /* Current state */
  smtp_auth_state_t auth_state; /* Current authentication state */
  /* Values that need to be saved because state machine can't be used during
   * tree dissection */
  uint8_t *username;     /* The username in the authentication. */
  gboolean crlf_seen;    /* Have we seen a CRLF on the end of a packet */
  gboolean data_seen;    /* Have we seen a DATA command yet */
  uint32_t msg_read_len; /* Length of BDAT message read so far */
  uint32_t msg_tot_len;  /* Total length of BDAT message */
  gboolean msg_last;     /* Is this the last BDAT chunk */
};

// convert smtp state to string
const gchar *smtp_state_to_str(smtp_state_t state) {
  for (int i = 0; i < SMTP_STATE_AWAITING_STARTTLS_RESPONSE; i++) {
    if (smtp_state_vals[i].value == state) {
      return smtp_state_vals[i].strptr;
    }
  }
  return "UNKNOWN";
}

// convert smtp auth state to string
const gchar *smtp_auth_state_to_str(smtp_auth_state_t state) {
  for (int i = 0; i < SMTP_AUTH_STATE_FAILED; i++) {
    if (smtp_auth_state_vals[i].value == state) {
      return smtp_auth_state_vals[i].strptr;
    }
  }
  return "UNKNOWN";
}

const gchar *smtp_response_code_to_str(guint32 code) {
  for (int i = 0;; i++) {
    if (smtp_response_codes[i].value == code) {
      return smtp_response_codes[i].strptr;
    } else if (smtp_response_codes[i].value == 0) {
      break;
    }
  }
  return "UNKNOWN";
}

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
        g_ascii_strncasecmp((const gchar *)command, commands[i].command,
                            commands[i].len) == 0)
      return TRUE;
  }
  return FALSE;
}
int length_eol(const guint8 *payload, int len, int offset,
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

int payload_find_line_end(const guint8 *tvb, const int offset, int len,
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
gint tvb_strneql(const guint8 *tvb, const gint offset, const gchar *str,
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
int smtp_decoder(const guint8 *tvb, gint tvb_size,
                 struct smtp_session_state *session_state, gboolean request,
                 int packet_number, Parsed_smtp *smtp_info) {

  printf("[Packet %d] %s\n", packet_number,
         request == 1 ? "Request" : "Response");

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
  guint8 line_code[3];

  if (tvb_size == 0) {
    return 0;
  }
  if (request) {

    /*
     * Create a frame data structure and attach it to the packet.
     */
    spd_frame_data =
        (struct smtp_proto_data *)malloc(sizeof(struct smtp_proto_data));

    spd_frame_data->pdu_type = SMTP_PDU_CMD;
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
            session_state->msg_read_len += tvb_size - loffset;
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
          decrypt = (u_char *)g_memdup2(tvb+loffset, linelen);
          if ((smtp_auth_parameter_decoding_enabled) &&
              (strlen((const char *)decrypt) > 1) &&
              (g_base64_decode_inplace((gchar *)decrypt, &decrypt_len)) &&
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
          if (g_ascii_strncasecmp((const gchar *)line, "DATA", 4) == 0) {
            /*
             * DATA command.
             * This is a command, but everything that comes after it,
             * until an EOM, is data.
             */
            spd_frame_data->pdu_type = SMTP_PDU_CMD;
            session_state->smtp_state = SMTP_STATE_READING_DATA;
            session_state->data_seen = TRUE;
            printf("DATA command seen\n");
          } else if (g_ascii_strncasecmp((const gchar *)line, "BDAT", 4) == 0) {
            /*
             * BDAT command.
             * This is a command, but everything that comes after it,
             * until given length is received, is data.
             */
            guint32 msg_len;

            msg_len = (guint32)strtoul((const char *)line + 5, NULL, 10);

            spd_frame_data->pdu_type = SMTP_PDU_CMD;
            session_state->data_seen = TRUE;
            session_state->msg_tot_len += msg_len;

            if (msg_len == 0) {
              /* No data to read, next will be a command */
              session_state->smtp_state = SMTP_STATE_READING_CMDS;
            } else {
              session_state->smtp_state = SMTP_STATE_READING_DATA;
            }

            if (g_ascii_strncasecmp((const gchar *)line + linelen - 4, "LAST",
                                    4) == 0) {
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
          } else if ((g_ascii_strncasecmp((const gchar *)line, "AUTH LOGIN",
                                          10) == 0) &&
                     (linelen <= 11)) {
            /*
             * AUTH LOGIN command.
             * Username is in a separate frame
             */
            spd_frame_data->pdu_type = SMTP_PDU_CMD;
            session_state->smtp_state = SMTP_STATE_READING_CMDS;
            session_state->auth_state = SMTP_AUTH_STATE_START;
            printf("    AUTH LOGIN command seen\n");
          } else if ((g_ascii_strncasecmp((const gchar *)line, "AUTH LOGIN",
                                          10) == 0) &&
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
            spd_frame_data->pdu_type = SMTP_PDU_CMD;
          }
        } else if (session_state->auth_state == SMTP_AUTH_STATE_USERNAME_REQ) {
          session_state->auth_state = SMTP_AUTH_STATE_USERNAME_RSP;
          printf("\tUsername: %s", line);
        } else if (session_state->auth_state == SMTP_AUTH_STATE_PASSWORD_REQ) {
          session_state->auth_state = SMTP_AUTH_STATE_PASSWORD_RSP;
          printf("\tPassword: %s", line);
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

      // printf("\tSMTP state: %s\n\tAUTH state: %s\n",
      //        smtp_state_to_str(session_state->smtp_state),
      //        smtp_auth_state_to_str(session_state->auth_state));
    }

    loffset = next_offset;
  }

  if (request) {

    /** Check out whether or not we can see a command in there ... */
    /** What we are looking for is not data_seen and the word DATA */
    /** and not eom_seen. */
    /**  */
    /** We will see DATA and session_state->data_seen when we process the */
    /** tree view after we have seen a DATA packet when processing */
    /** the packet list pane. */
    /**  */
    /** On the first pass, we will not have any info on the packets */
    /** On second and subsequent passes, we will. */

    switch (spd_frame_data->pdu_type) {
    case SMTP_PDU_MESSAGE:
      length_remaining = tvb_size - offset;
      if (TRUE) {
        // add tvb to fragments list in smtp_info
        smtp_info->fragments =
            g_slist_append(smtp_info->fragments, (guchar *)tvb);
        smtp_info->num_fragments++;
        smtp_info->defragment_size += tvb_size;
        printf("\tSize of defragmented message: %d\n",tvb_size);
      }
      break;
    case SMTP_PDU_EOM:
      printf("\tEOM seen\n");
      if (loffset) {
        // add tvb to fragments list in smtp_info
        smtp_info->fragments =
            g_slist_append(smtp_info->fragments, (guchar *)tvb);
        smtp_info->num_fragments++;
        // ignore the EOM in the defragmented message, so the size is loffset, not tvb_size
        smtp_info->defragment_size += loffset;
        printf("\tSize of defragmented message: %d\n",tvb_size);
      }
      break;
    case SMTP_PDU_CMD:

      /** Command. */
      /**  */
      /** XXX - what about stuff after the first line? */
      /** Unlikely, as the client should wait for a response to the */
      /** previous command before sending another request, but we */
      /** should probably handle it. */

      loffset = offset;
      while (loffset < tvb_size) {

        /** Find the end of the line. */

        linelen = payload_find_line_end(tvb, loffset, tvb_size - loffset,
                                        &next_offset);

        if (session_state->auth_state == SMTP_AUTH_STATE_USERNAME_RSP) {

          // copy decrypt to session_state->username
          smtp_info->username = (guint8 *)g_malloc(linelen + 1);
          smtp_info->username[linelen]= '\0';
          memcpy(smtp_info->username, tvb, linelen);
        } else if (session_state->auth_state == SMTP_AUTH_STATE_PASSWORD_RSP) {

          // copy decrypt to session_state->password
          smtp_info->password = (guint8 *)g_malloc(linelen + 1);
          smtp_info->password[linelen]= '\0';
          memcpy(smtp_info->password, tvb, linelen);
        }

        loffset = next_offset;
      }
    }
  } else {
    // Multiline information
    smtp_multiline_state_t multiline_state = SMTP_MULTILINE_NONE;
    guint32 multiline_code = 0;

    while (offset < tvb_size) {
      // Find the end of the line.
      linelen =
          payload_find_line_end(tvb, offset, tvb_size - offset, &next_offset);
      /** printf("linelen: %d\n", linelen); */

      if (linelen >= 3) {
        line_code[0] = *(tvb + offset);
        line_code[1] = *(tvb + offset + 1);
        line_code[2] = *(tvb + offset + 2);

        if (g_ascii_isdigit(line_code[0]) && g_ascii_isdigit(line_code[1]) &&
            g_ascii_isdigit(line_code[2])) {

          code = (line_code[0] - '0') * 100 + (line_code[1] - '0') * 10 +
                 (line_code[2] - '0');
          if ((linelen > 3) && (*(tvb + offset + 3) == '-')) {
            if (multiline_state == SMTP_MULTILINE_NONE) {
              multiline_state = SMTP_MULTILINE_START;
              multiline_code = code;
            } else {
              multiline_state = SMTP_MULTILINE_CONTINUE;
            }
          } else if ((multiline_state == SMTP_MULTILINE_START) ||
                     (multiline_state == SMTP_MULTILINE_CONTINUE)) {
            multiline_state = SMTP_MULTILINE_END;
          }

          printf("\tCode: %d,Meaning: %s\n", code,
                 smtp_response_code_to_str(code));
          /** If we're awaiting the response to a STARTTLS code, this */
          /** is it - if it's 220, all subsequent traffic will */
          /** be TLS, otherwise we're back to boring old SMTP. */

          if (session_state->smtp_state ==
              SMTP_STATE_AWAITING_STARTTLS_RESPONSE) {
            if (code == 220) {
              /* This is the last non-TLS frame. */
              /** ssl_starttls_ack(tls_handle, pinfo, smtp_handle); */
            }
            session_state->smtp_state = SMTP_STATE_READING_CMDS;
          }

          if (code == 334) {
            switch (session_state->auth_state) {
            case SMTP_AUTH_STATE_START:
              session_state->auth_state = SMTP_AUTH_STATE_USERNAME_REQ;
              break;
            case SMTP_AUTH_STATE_USERNAME_RSP:
              session_state->auth_state = SMTP_AUTH_STATE_PASSWORD_REQ;
              break;
            case SMTP_AUTH_STATE_PLAIN_REQ:
              session_state->auth_state = SMTP_AUTH_STATE_PLAIN_RSP;
              break;
            case SMTP_AUTH_STATE_PLAIN_START_REQ:
              session_state->auth_state = SMTP_AUTH_STATE_PLAIN_REQ;
              break;
            case SMTP_AUTH_STATE_NTLM_REQ:
              session_state->auth_state = SMTP_AUTH_STATE_NTLM_CHALLANGE;
              break;
            case SMTP_AUTH_STATE_NONE:
            case SMTP_AUTH_STATE_USERNAME_REQ:
            case SMTP_AUTH_STATE_PASSWORD_REQ:
            case SMTP_AUTH_STATE_PASSWORD_RSP:
            case SMTP_AUTH_STATE_PLAIN_RSP:
            case SMTP_AUTH_STATE_PLAIN_CRED_REQ:
            case SMTP_AUTH_STATE_NTLM_RSP:
            case SMTP_AUTH_STATE_NTLM_CHALLANGE:
            case SMTP_AUTH_STATE_SUCCESS:
            case SMTP_AUTH_STATE_FAILED:
              /* ignore */
              break;
            }
          } else if ((session_state->auth_state ==
                      SMTP_AUTH_STATE_PASSWORD_RSP) ||
                     (session_state->auth_state == SMTP_AUTH_STATE_PLAIN_RSP) ||
                     (session_state->auth_state == SMTP_AUTH_STATE_NTLM_RSP) ||
                     (session_state->auth_state ==
                      SMTP_AUTH_STATE_PLAIN_CRED_REQ)) {
            if (code == 235) {
              session_state->auth_state = SMTP_AUTH_STATE_SUCCESS;
            } else {
              session_state->auth_state = SMTP_AUTH_STATE_FAILED;
            }
          }

          // printf("\tSMTP state: %s\n\tAUTH state: %s\n",
          //        smtp_state_to_str(session_state->smtp_state),
          //        smtp_auth_state_to_str(session_state->auth_state));
        }

        // Clear multiline state if this is the last line
        if (multiline_state == SMTP_MULTILINE_END)
          multiline_state = SMTP_MULTILINE_NONE;
      }

      /*
       * Step past this line.
       */
      offset = next_offset;
    }
  }
  printf("\tSMTP state: %s\n\tAUTH state: %s\n",
         smtp_state_to_str(session_state->smtp_state),
         smtp_auth_state_to_str(session_state->auth_state));
  /** printf("payload: %s\n", tvb); */
  printf(
      "------------------------------------------------------------------\n");
  return 0;
}

#endif
