#ifndef DISSECT_FTP_H
#define DISSECT_FTP_H

#include "handler.h"
#include <string.h>
#include <ctype.h>
#include <glib.h>

typedef struct _ftp_data_conversation_s
{
  /* Command that this data answers */
  const gchar *command;

  /* Frame command was seen */
  guint32 command_frame;

  /* Type of command used to set up data conversation */
  const gchar *setup_method;

  /* Frame where this happened */
  guint32 setup_frame;

  /* Where file will be sent or received */
  const gchar *current_working_directory;

  /* Where file contents will be stored here */
  const gchar *file_content;

} ftp_data_conversation_t;

typedef struct _ftp_conversation_s
{
  /* Most recent request cmd seen */
  gchar *last_cmd;

  /* Frame of most recent cmd */
  guint32 last_cmd_frame;

  /* Where file will be sent or received */
  gchar *current_working_directory;

  /* Current data conversation */
  ftp_data_conversation_t *current_data_conv;

  /* Frame of cmd that needs a new conversation like LIST, PASV, STOR */
  guint32 current_data_setup_frame;

  /* Username of client side */
  gchar *username;

  /* Frame containing username */
  guint32 username_frame;

  /* Authentication state, see ftp_auth_state_t */
  guint8 auth_state;

  /* Is the conversation encoded? 0: no, 1: pending req, 2: yes, -1: other*/
  guint8 encode_tls;

  /* FTP return code */
  gint16 last_return_code;

} ftp_conversation_t;

typedef struct _value_string
{
  guint32 value;
  const gchar *strptr;
} value_string;

typedef struct tvbuff
{
  const guint8 *real_data;
  guint32 length;
} tvbuff_t;

typedef enum
{
  FTP_AUTH_STATE_NONE,          /* No authentication seen or used */
  FTP_AUTH_STATE_START,         /* Authentication started, waiting for username */
  FTP_AUTH_STATE_USERNAME_SENT, /* Sent username */
  FTP_AUTH_STATE_USERNAME_RSP,  /* Received username */
  FTP_AUTH_STATE_PASSWORD_SENT, /* Sent password */
  FTP_AUTH_STATE_FAILED,        /* Authentication failed, no decoding */
  FTP_AUTH_STATE_SUCCESS        /* Authentication successful, start decoding */
} ftp_auth_state_t;

guint16 get_token_len(const u_char *cmd, const u_char *cmd_end, u_char *token, const u_char **next_token);

gint16 get_return_code(const u_char *rsp, const u_char *rsp_end, const u_char **next_token);

gint32 dissect_ftp(parsed_payload *pp, ftp_conversation_t *ftp_conv, flow_base_t *flow, FILE *stream);

void inspect_flow(HashTable table, flow_base_t *flow, FILE *stream);

#endif /* DISSECT_FTP_H */