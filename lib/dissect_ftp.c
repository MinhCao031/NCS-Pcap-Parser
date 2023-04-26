#include "dissect_ftp.h"

static const value_string response_table[] = {
    {110, "Restart marker reply"},
    {120, "Service ready in nnn minutes"},
    {125, "Data connection already open; transfer starting"},
    {150, "File status okay; about to open data connection"},
    {200, "Command okay"},
    {202, "Command not implemented, superfluous at this site"},
    {211, "System status, or system help reply"},
    {212, "Directory status"},
    {213, "File status"},
    {214, "Help message"},
    {215, "NAME system type"},
    {220, "Service ready for new user"},
    {221, "Service closing control connection"},
    {225, "Data connection open; no transfer in progress"},
    {226, "Closing data connection"},
    {227, "Entering Passive Mode"},
    {228, "Entering Long Passive Mode"},
    {229, "Entering Extended Passive Mode"},
    {230, "User logged in, proceed"},
    {232, "User logged in, authorized by security data exchange"},
    {234, "Security data exchange complete"},
    {235, "Security data exchange completed successfully"},
    {250, "Requested file action okay, completed"},
    {257, "PATHNAME created"},
    {331, "User name okay, need password"},
    {332, "Need account for login"},
    {334, "Requested security mechanism is ok"},
    {335, "Security data is acceptable, more is required"},
    {336, "Username okay, need password. Challenge is ..."},
    {350, "Requested file action pending further information"},
    {421, "Service not available, closing control connection"},
    {425, "Can't open data connection"},
    {426, "Connection closed; transfer aborted"},
    {430, "Invalid username or password"},
    {431, "Need some unavailable resource to process security"},
    {434, "Requested host unavailable"},
    {450, "Requested file action not taken"},
    {451, "Requested action aborted: local error in processing"},
    {452, "Requested action not taken. Insufficient storage space in system"},
    {500, "Syntax error, command unrecognized"},
    {501, "Syntax error in parameters or arguments"},
    {502, "Command not implemented"},
    {503, "Bad sequence of commands"},
    {504, "Command not implemented for that parameter"},
    {522, "Network protocol not supported"},
    {530, "Not logged in"},
    {532, "Need account for storing files"},
    {533, "Command protection level denied for policy reasons"},
    {534, "Request denied for policy reasons"},
    {535, "Failed security check (hash, sequence, etc)"},
    {536, "Requested PROT level not supported by mechanism"},
    {537, "Command protection level not supported by security mechanism"},
    {550, "Requested action not taken: File unavailable"},
    {551, "Requested action aborted: page type unknown"},
    {552, "Requested file action aborted: Exceeded storage allocation"},
    {553, "Requested action not taken: File name not allowed"},
    {631, "Integrity protected reply"},
    {632, "Confidentiality and integrity protected reply"},
    {633, "Confidentiality protected reply"},
    {0, NULL}};

guint16 get_token_len(const u_char *cmd, const u_char *cmd_end, u_char *token,
                      const u_char **next_token) {
  const u_char *cmd_start;
  guint16 token_len = 0;
  cmd_start = cmd;

  if (!token)
    token = malloc(sizeof(char *));

  /* Search for a blank, a CR or an LF, or the end of the buffer. */
  while (cmd < cmd_end && *cmd != ' ' && *cmd != '\r' && *cmd != '\n') {
    *token = *cmd;
    token++;
    cmd++;
  }
  token_len = (gint32)(cmd - cmd_start);
  *token = '\0';

  /* Skip trailing blanks. */
  while (cmd < cmd_end && (*cmd == ' ' || *cmd == '\r' || *cmd == '\n'))
    cmd++;

  *next_token = cmd;

  return token_len;
}

/* Get the return code from response, return 0 if not valid or not a number. */
gint16 get_return_code(const u_char *rsp, const u_char *rsp_end,
                       const u_char **next_token) {
  gint16 return_code = 0;
  gint8 is_code_valid = -1;

  /* Search for a number */
  while (isdigit(*rsp) && rsp < rsp_end) {
    return_code = return_code * 10 + (gint16)(*rsp) - '0';
    rsp++;
  }

  for (int i = 0; i < 58; i++) {
    if (response_table[i].value == return_code) {
      /* Skip trailing blanks. */
      while (rsp < rsp_end &&
             (*rsp == '-' || *rsp == ' ' || *rsp == '\r' || *rsp == '\n'))
        rsp++;
      *next_token = rsp;
      is_code_valid = 1;
      break;
    }
  }

  return is_code_valid * return_code;
}

u_char *process_pwd_rsp(const u_char *rsp, const u_char *rsp_end,
                        u_char **cwd) {
  gint8 found_cwd = 0;
  u_char *token = malloc(sizeof(u_char));
  guint16 length = 0;
  const u_char *cwd_left = NULL;
  const u_char *cwd_right = NULL;
  // LOG_DBG(LOG_DISEC, 1, "Before: \"%s\"\n", *cwd);
  // LOG_DBG(LOG_DISEC, 1, "Start: \"%s\"\n", rsp);

  for (const u_char *rsp_iter = rsp; rsp_iter < rsp_end; rsp_iter++) {
    if (found_cwd == 0 && *rsp_iter == '"' && !cwd_left) {
      cwd_left = rsp_iter + 1;
      found_cwd = 1;
    } else if (found_cwd == 1 && *rsp_iter != '"') {
      *(token + length) = *rsp_iter;
      length++;
    } else if (found_cwd == 1 && *rsp_iter == '"' && cwd_left) {
      cwd_right = rsp_iter;
      *(token + length) = '\0';
      found_cwd = 2;
      break;
    }
  }
  // LOG_DBG(LOG_DISEC, cwd_right, "Len: ###%hu###\n", length);
  *cwd = token;
  // LOG_DBG(LOG_DISEC, cwd_left, "Cwd: #%s~#%s~#%s~\n", *cwd, token, rsp);

  return found_cwd > 1 ? token : NULL;
}

static gboolean parse_port_pasv(const u_char *line,
                                guint32 *ftp_ip, guint16 *ftp_port,
                                guint *ftp_ip_len, guint *ftp_port_len) {
  u_char c;
  u_char *p = line;
  int i, ip_address[4], port[2];
  gboolean ans = FALSE;

  for (;;) {
    LOG_DBG(LOG_DISEC, 1, "\nScanning: %s\n", p);

    /* Look for a digit. */
    while ((c = *p) != '\0' && !isdigit(c)) p++;

    if (*p == '\0') {
      /* We ran out of text without finding anything. */
      break;
    }

    /* See if we have six numbers. */
    i = sscanf(p, "%d,%d,%d,%d,%d,%d", &ip_address[0], &ip_address[1],
               &ip_address[2], &ip_address[3], &port[0], &port[1]);
    if (i >= 6) {
      /* We have a winner! */
      *ftp_port = ((port[0] & 0xFF) << 8) | (port[1] & 0xFF);
      *ftp_ip = (ip_address[3] << 24) | (ip_address[2] << 16) | (ip_address[1] << 8) | ip_address[0];
      *ftp_port_len = (port[0] < 10 ? 1 : (port[0] < 100 ? 2 : 3)) + 1 +
                      (port[1] < 10 ? 1 : (port[1] < 100 ? 2 : 3));
      *ftp_ip_len =
          (ip_address[0] < 10 ? 1 : (ip_address[0] < 100 ? 2 : 3)) + 1 +
          (ip_address[1] < 10 ? 1 : (ip_address[1] < 100 ? 2 : 3)) + 1 +
          (ip_address[2] < 10 ? 1 : (ip_address[2] < 100 ? 2 : 3)) + 1 +
          (ip_address[3] < 10 ? 1 : (ip_address[3] < 100 ? 2 : 3));
      ans = TRUE;
      break;
    }

    /* Well, not enough. Skip the first number we found, and keep trying. */
    while ((c = *p) != '\0' && isdigit(c))
      p++;
  }

  return ans;
}

gint32 dissect_ftp(parsed_payload *pp, ftp_conversation_t *p_ftp_conv,
                   flow_base_t *flow, FILE *stream) {
  tvbuff_t tvb = (tvbuff_t){.real_data = pp->data, .length = pp->data_len};

  gboolean is_request = pp->is_up;
  guint32 packet_frame = pp->index;
  const u_char *line = tvb.real_data;
  guint32 datalen = tvb.length;
  const u_char *token = malloc(sizeof(u_char *));
  guint16 tokenlen;
  const u_char *next_token;

  guint8 *auth_state = &(p_ftp_conv->auth_state);
  guint8 *encode_tls = &(p_ftp_conv->encode_tls);
  u_char **cwdir = &(p_ftp_conv->current_working_directory);
  u_char **last_cmd = &(p_ftp_conv->last_cmd);
  guint32 *last_cmd_frame = &(p_ftp_conv->last_cmd_frame);
  gint16 *last_return_code = &(p_ftp_conv->last_return_code);
  gint16 code = 0;
  gboolean is_port_request = FALSE;
  gboolean is_eprt_request = FALSE;
  gboolean is_pasv_response = FALSE;
  gboolean is_epasv_response = FALSE;
  gint32 offset;
  gint32 next_offset;
  guint32 pasv_ip;
  // guint32 pasv_offset;
  guint32 ftp_ip;
  guint32 ftp_ip_len;
  // guint32 eprt_offset;
  guint32 eprt_af = 0;
  guint32 eprt_ip;
  guint32 eprt_ip_len = 0;
  guint16 ftp_port;
  guint32 ftp_port_len;
  gboolean ftp_nat;

  LOG_DBG(stream, DBG_DISSECT,
          "------------------------------------------------------\n");
  LOG_DBG(stream, DBG_DISSECT, "[Packet %d] %s\n", packet_frame,
          is_request ? "Request" : "Response");
  // LOG_DBG(stream, DBG_DISSECT,"FTP conversation BEFORE:\n\t"
  //         "Last cmd: \"%s\"\n\tLast cmd frame: \"%u\"\n\t"
  //         "CWD: \"%s\"\n\tCurrent data setup frame: \"%u\"\n\t"
  //         "Username: \"%s\"\n\tUsername frame: \"%u\"\n\t"
  //         "Auth state: \"%hhu\"\n\tTLS state: \"%hhu\"\n\tLast return code:
  //         \"%u\"\n", p_ftp_conv->last_cmd, p_ftp_conv->last_cmd_frame,
  //         p_ftp_conv->current_working_directory,
  //         p_ftp_conv->current_data_setup_frame, p_ftp_conv->username,
  //         p_ftp_conv->username_frame, p_ftp_conv->auth_state,
  //         p_ftp_conv->encode_tls, p_ftp_conv->last_return_code
  // );

  if (is_request) {
    // LOG_DBG(stream, DBG_DISSECT, "*01*");
    tokenlen = get_token_len(line, line + datalen, token, &next_token);
    // LOG_DBG(stream, DBG_DISSECT, "*02*");
    if (tokenlen > 0) {
      // LOG_DBG(stream, DBG_DISSECT, "*03*");
      // LOG_DBG(stream, DBG_DISSECT, "Request: {%s}\n", line);
      strncpy(*last_cmd, token, tokenlen + 1);
      // LOG_DBG(stream, DBG_DISSECT, "*16*");
      *last_cmd_frame = packet_frame;
      // LOG_DBG(stream, DBG_DISSECT, "*17*");
      if (strncmp(line, "PORT", tokenlen) == 0) {
        is_port_request = TRUE;
        LOG_DBG(stream, DBG_DISSECT, "PORT command\n");
      } else if (strncmp(line, "EPRT", tokenlen) == 0) {
        is_eprt_request = TRUE;
        LOG_DBG(stream, DBG_DISSECT, "EPRT command\n");
      } else if (strncmp(line, "USER", tokenlen) == 0) {
        // LOG_DBG(stream, DBG_DISSECT, "*18*");
        if (datalen - tokenlen > 1) {
          // LOG_DBG(stream, DBG_DISSECT, "*20*");
          tokenlen =
              get_token_len(next_token, line + datalen, token, &next_token);
          // LOG_DBG(stream, DBG_DISSECT, "*21*");
          strncpy(p_ftp_conv->username, token, tokenlen + 1);
          // LOG_DBG(stream, DBG_DISSECT, "*22*");
          p_ftp_conv->username_frame = packet_frame;
          *auth_state = FTP_AUTH_STATE_USERNAME_SENT;
        } else {
          LOG_DBG(stream, DBG_DISSECT, "Cmd USER exception: got {%s}\n", line);
        }
        // LOG_DBG(stream, DBG_DISSECT, "*19*");
      } else if (strncmp(line, "PASS", tokenlen) == 0) {
        if (strlen(p_ftp_conv->username) > 0 && p_ftp_conv->username_frame) {
          *auth_state = FTP_AUTH_STATE_PASSWORD_SENT;
        } else {
          LOG_DBG(stream, DBG_DISSECT,
                  "Cmd PASS exception: Username required\n");
          *auth_state = FTP_AUTH_STATE_START;
        }
      } else if (strncmp(line, "AUTH", tokenlen) == 0) {
        if ((datalen == 8) && strncmp("AUTH TLS", (u_char *)line, 8) == 0) {
          *encode_tls = 1;
          LOG_DBG(stream, DBG_DISSECT, "TLS requested\n");
        } else {
          tokenlen =
              get_token_len(next_token, line + datalen, token, &next_token);
          LOG_DBG(stream, DBG_DISSECT, "AUTH type: {%s}\n", token);
        }
      }
    } else {
      LOG_DBG(stream, DBG_DISSECT, "No data\n");
    }
    // LOG_DBG(stream, DBG_DISSECT, "*04*");
  } else {
    // LOG_DBG(stream, DBG_DISSECT, "*05*");
    // LOG_DBG(stream, DBG_DISSECT, "Response: {%s}\n", line);
    // LOG_DBG(stream, DBG_DISSECT, "*06*");
    if (datalen >= 3) {
      // LOG_DBG(stream, DBG_DISSECT, "*10*");
      code = get_return_code(line, line + datalen, &next_token);
      // LOG_DBG(stream, DBG_DISSECT, "*11*");
      if (code <= 0) {
        LOG_DBG(stream, DBG_DISSECT, "Return code %hd is not valid!\n", code);
      } else {
        LOG_DBG(stream, DBG_DISSECT, "*13*");
        *last_return_code = code;
        // LOG_DBG(stream, DBG_DISSECT, "*14*");
        // LOG_DBG(stream, DBG_DISSECT, "*15*");
        if (code == 220) /* Introduce */
        {
          // LOG_DBG(stream, DBG_DISSECT, "*12*");
          LOG_DBG(stream, DBG_DISSECT, "Welcome\n");
        }
        if (code == 227) /* PASV */
        {
          LOG_DBG(stream, DBG_DISSECT, "*30*");
          is_pasv_response = TRUE;
          if (parse_port_pasv(next_token, &ftp_ip, &ftp_port, &ftp_ip_len, &ftp_port_len)) {
            p_ftp_conv->current_data_setup_frame = packet_frame;
            LOG_DBG(stream, DBG_DISSECT, "Passive mode:\nIP: %X\nPort: %u\n", ftp_ip, ftp_port);
          }
        }
        if (code == 229) /* EPSV */
          is_epasv_response = TRUE;
        if (code == 230) /* PASS */
          *auth_state = FTP_AUTH_STATE_SUCCESS;
        if (code == 234) /* AUTH */
        {
          if (*encode_tls == 1) {
            LOG_DBG(stream, DBG_DISSECT, "AUTH TLS accepted");
            p_ftp_conv->encode_tls = 2;
          } else {
            tokenlen =
                get_token_len(next_token, line + datalen, token, &next_token);
            LOG_DBG(stream, DBG_DISSECT, "AUTH %s accepted", token);
            p_ftp_conv->encode_tls = -1;
          }
        }
        if (code == 250) /* CWD */
        {
        }
        if (code == 257) /* PWD */
        {
          // LOG_DBG(stream, DBG_DISSECT, "*23*");
          *cwdir = process_pwd_rsp(next_token, line + datalen, cwdir);
          // LOG_DBG(stream, DBG_DISSECT, "*24*");
          if (datalen > 4 && *cwdir) {
            LOG_DBG(stream, DBG_DISSECT, "CWD: got {%s}", *cwdir);
          } else {
            LOG_DBG(stream, DBG_DISSECT,
                    "Invalid response: datalen = %u, found = %s", datalen,
                    *cwdir);
          }
        }
        if (code == 331) {
          *auth_state = FTP_AUTH_STATE_USERNAME_RSP;
        }
        if (code == 530) {
          *auth_state = FTP_AUTH_STATE_FAILED;
        }
      }
    }
  }

  LOG_DBG(stream, DBG_DISSECT,
          "\nFTP conversation:\n\t"
          "Last cmd: \"%s\"\n\tLast cmd frame: \"%u\"\n\t"
          "CWD: \"%s\"\n\tCurrent data setup frame: \"%u\"\n\t"
          "Username: \"%s\"\n\tUsername frame: \"%u\"\n\t"
          "Auth state: \"%hhu\"\n\tTLS state: \"%hhu\"\n\tLast return code: "
          "\"%u\"\n",
          p_ftp_conv->last_cmd, p_ftp_conv->last_cmd_frame,
          p_ftp_conv->current_working_directory,
          p_ftp_conv->current_data_setup_frame, p_ftp_conv->username,
          p_ftp_conv->username_frame, p_ftp_conv->auth_state,
          p_ftp_conv->encode_tls, p_ftp_conv->last_return_code);
  return datalen;
}

void inspect_flow(HashTable table, flow_base_t *flow, FILE *stream) {
  if (flow == NULL) {
    printf("ERROR: flow is null\n");
    return;
  }
  Node const *temp = flow->head_flow;

  ftp_conversation_t ftp_conv = (ftp_conversation_t){
      .last_cmd = malloc(sizeof(char)), // calloc(5, sizeof(char)),
      .last_cmd_frame = 0,
      .current_working_directory = "??????\0",
      .current_data_conv = malloc(sizeof(ftp_data_conversation_t)),
      .current_data_setup_frame = 0,
      .username = malloc(sizeof(char)), // calloc(32, sizeof(char)),
      .username_frame = 0,
      .auth_state = FTP_AUTH_STATE_NONE,
      .encode_tls = 0,
      .last_return_code = 0,
  };

  // print all payloads in flow->head_flow

  while (temp != NULL) {
    gint32 ans = dissect_ftp(PP_IN_NODE(temp), &ftp_conv, flow, stream);
    LOG_DBG(stream, DBG_DISSECT, "Dissected length: %d\n", ans);
    temp = temp->next;
  }

  // u_char *defragment = NULL;
  // // print fragments
  // if (smtp_info.num_fragments > 0)
  // {
  //   print("###Username: %.*s\n", smtp_info.username.length,
  //          smtp_info.username.real_data);
  //   print("###Password: %.*s\n", smtp_info.password.length,
  //          smtp_info.password.real_data);
  //   print("###Num Fragments: %d\n", smtp_info.num_fragments);
  //   print("###Content length: %ld\n", smtp_info.defragment_size);

  //   // print("Fragments:\n");
  //   // print all fragments in smtp_info->fragments, note that this is GSList
  //   // int i = 0;
  //   // for (GSList *temp = smtp_info->fragments; temp != NULL; temp =
  //   // temp->next) {
  //   //   i++;
  //   //   print("%s\n", ((gchar *)temp->data));
  //   //   print("Fragment %d length: %ld\n", i, strlen((gchar *)temp->data));
  //   // }

  //   // merge all fragments in smtp_info->fragments to one string
  //   defragment = g_malloc(smtp_info.defragment_size + 1);
  //   size_t offset = 0;
  //   for (GSList *temp = smtp_info.fragments; temp != NULL; temp = temp->next)
  //   {
  //     // memcpy(defragment + offset, temp->data, strlen(temp->data));
  //     // using strcpy instead of memcpy to avoid copying \0 characters
  //     // strcpy((char *)defragment + offset, (char *)temp->data);
  //     strncpy((char *)defragment + offset, (char *)temp->data,
  //             strlen(temp->data) + 1);

  //     offset += strlen(temp->data);
  //   }
  //   defragment[smtp_info.defragment_size] = '\0';

  //   // print defragment
  //   // print("%s\n", defragment);
  //   // g_free(defragment);
  // }

  // tvbuff_t tvb =
  //     (tvbuff_t){.real_data = defragment, .length =
  //     smtp_info.defragment_size};

  // dissect_imf(&tvb);
  // // free defragment
  // g_free(defragment);
}
