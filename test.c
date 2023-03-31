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

static void dissect_imf_mailbox();
static void dissect_imf_address();
static void dissect_imf_address_list();
static void dissect_imf_mailbox_list();
static void dissect_imf_siolabel();

enum field {
  IMF_FIELD_CONTENT_TYPE,
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
  IMF_FIELD_MIME_VERSION,
  IMF_FIELD_DATE,
  IMF_FIELD_USER_AGENT,
  IMF_FIELD_CONTENT_LANGUAGE,
  IMF_FIELD_UNKNOWN,
  NOPE,
};
struct imf_field {
  const char *name;
  enum field hf_id;
  void (*dissect)();
};
static struct imf_field imf_fields[] = {

    {"content-type", IMF_FIELD_CONTENT_TYPE, NO_SUBDISSECTION},
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
    {"mime-version", IMF_FIELD_MIME_VERSION, dissect_imf_address},
    {"date", IMF_FIELD_DATE, NO_SUBDISSECTION},
    {"user-agent", IMF_FIELD_USER_AGENT, NO_SUBDISSECTION},
    {"content-language", IMF_FIELD_CONTENT_LANGUAGE, NO_SUBDISSECTION},
    {NULL, NOPE, NULL}};

static void dissect_imf_mailbox(){};
static void dissect_imf_address(){};
static void dissect_imf_address_list(){};
static void dissect_imf_mailbox_list(){};
static void dissect_imf_siolabel(){};

// find index if charactor in string
static int tvb_find_char(const u_char *tvb, int start_offset, int max_length,
                         const char needle) {

  const guint8 *result;
  guint limit = 0;

  limit = max_length;
  /* Only search to end of tvbuff, w/o throwing exception. */
  if (max_length >= 0 && limit > (guint)max_length) {
    /* Maximum length doesn't go past end of tvbuff; search
       to that value. */
    limit = (guint)max_length;
  }

  /* If we have real data, perform our search now. */
  if (tvb) {
    result = (const guint8 *)memchr(tvb + start_offset, needle, limit);
    if (result == NULL) {
      return -1;
    } else {
      return (gint)(result - tvb);
    }
  }
  // for (int i = start_offset; i < max_length; i++) {
  //   if (tvb[i] == c) {
  //     return i;
  //   }
  // }
  // return -1;
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

static void dissect_imf_content_type(const u_char *tvb, int offset, int length,
                                     guint8 **type, guint8 **parameters) {
  int first_colon;
  int end_offset;
  int len;
  int i;

  /* first strip any whitespace */
  for (i = 0; i < length; i++) {
    if (!g_ascii_isspace(*(tvb + offset + i))) {
      offset += i;
      break;
    }
  }

  /* find the first colon - there has to be a colon as there will have to be a
   * boundary */
  first_colon = tvb_find_char(tvb, offset, length, ';');

  if (first_colon != -1) {

    len = first_colon - offset;

    // allocate memory for type
    *type = (guint8 *)malloc(len + 1);
    // copy string from tvb with length len to type
    memcpy((void *)*type, tvb + offset, len);
    // add null terminator
    *(*type + len) = '\0';

    end_offset =
        imf_find_field_end(tvb, first_colon + 1, offset + length, NULL);
    if (end_offset == -1) {
      /* No end found */
      return;
    }
    len = end_offset - (first_colon + 1) - 2; /* Do not include the last CRLF */

    // allocate memory for parameters
    *parameters = (guint8 *)malloc(len + 1);
    // copy string from tvb with length len to parameters
    memcpy((void *)*parameters, tvb + first_colon + 1, len);
    // add null terminator
    *(*parameters + len) = '\0';
  }
}

typedef struct {
  const char *type;      /* Type of multipart */
  char *boundary;        /* Boundary string (enclosing quotes removed if any) */
  guint boundary_length; /* Length of the boundary string */
  char *protocol; /* Protocol string if encrypted multipart (enclosing quotes
                     removed if any) */
  guint protocol_length;   /* Length of the protocol string  */
  char *orig_content_type; /* Content-Type of original message */
  char *orig_parameters;   /* Parameters for Content-Type of original message */
} multipart_info_t;

typedef enum _http_type {
  HTTP_REQUEST,
  HTTP_RESPONSE,
  HTTP_NOTIFICATION,
  HTTP_OTHERS,
  SIP_DATA /* If the content is from the SIP dissector*/
} http_type_t;

/** Passed to dissectors called by the HTTP dissector. */
typedef struct _http_message_info_t {
  http_type_t
      type; /**< Message type; may be HTTP_OTHERS if not called by HTTP */
  const char *media_str;  /**< Content-Type parameters */
  const char *content_id; /**< Content-ID parameter */
  void *data; /**< The http_type is used to indicate the data transported */
} http_message_info_t;

static const char *ws_get_next_media_type_parameter(const char *pos,
                                                    gsize *retnamelen,
                                                    const char **retvalue,
                                                    gsize *retvaluelen,
                                                    const char **nextp) {
  const char *p, *namep, *valuep;
  char c;

  p = pos;
  while ((c = *p) != '\0' && g_ascii_isspace(c))
    p++; /* Skip white space */

  if (c == '\0') {
    /* No more parameters left */
    return NULL;
  }

  namep = p;

  /* Look for a '\0' (end of string), '=' (end of parameter name,
     beginning of parameter value), or ';' (end of parameter). */
  while ((c = *p) != '\0' && c != '=' && c != ';')
    p++;
  *retnamelen = (gsize)(p - namep);
  if (c == '\0') {
    /* End of string, so end of parameter, no parameter value */
    if (retvalue != NULL)
      *retvalue = NULL;
    if (retvaluelen != NULL)
      *retvaluelen = 0;
    *nextp = p;
    return namep;
  }
  if (c == ';') {
    /* End of parameter, no parameter value */
    if (retvalue != NULL)
      *retvalue = NULL;
    if (retvaluelen != NULL)
      *retvaluelen = 0;
    *nextp = p + 1;
    return namep;
  }
  /* The parameter has a value.  Skip the '=' */
  p++;
  valuep = p;
  if (retvalue != NULL)
    *retvalue = valuep;
  /* Is the value a quoted string? */
  if (*p == '"') {
    /* Yes. Skip the opening quote, and scan forward looking for
       a non-escaped closing quote. */
    p++;
    for (;;) {
      c = *p;
      if (c == '\0') {
        /* End-of-string.  We're done.
           (XXX - this is an error.) */
        if (retvaluelen != NULL) {
          *retvaluelen = (gsize)(p - valuep);
        }
        *nextp = p;
        return namep;
      }
      if (c == '"') {
        /* Closing quote.  Skip it; we're done with
           the quoted-string. */
        p++;
        break;
      }
      if (c == '\\') {
        /* Backslash; this escapes the next character
           (quoted-pair). Skip the backslash, and make
           sure there *is* a next character. */
        p++;
        if (*p == '\0') {
          /* Nothing left; we're done.
             (XXX - this is an error.) */
          break;
        }
      }
      /* Skip the character we just processed. */
      p++;
    }
    /* Now scan forward looking for a '\0' (end of string)
       or ';' (end of parameter), in case there's any
        extra cruft after the quoted-string. */
    while ((c = *p) != '\0' && c != ';')
      p++;
  } else {
    /* No.  Just scan forward looking for a '\0' (end
       of string) or ';' (end of parameter). */
    while ((c = *p) != '\0' && c != ';')
      p++;
  }
  if (c == '\0') {
    /* End of string, so end of parameter */
    if (retvaluelen != NULL) {
      *retvaluelen = (gsize)(p - valuep);
    }
    *nextp = p;
    return namep;
  }
  /* End of parameter; point past the terminating ';' */
  if (retvaluelen != NULL) {
    *retvaluelen = (gsize)(p - valuep);
  }
  *nextp = p + 1;
  return namep;
}
char *ws_find_media_type_parameter(const char *parameters, const char *key) {
  const char *p, *name, *value;
  char c;
  gsize keylen, namelen, valuelen;
  char *valuestr, *vp;

  if (parameters == NULL || key == NULL)
    /* we won't be able to find anything */
    return NULL;

  keylen = (gsize)strlen(key);
  if (keylen == 0) {
    /* There's no parameter name to searh for */
    return NULL;
  }
  p = parameters;
  if (*p == '\0') {
    /* There are no parameters in which to search */
    return NULL;
  }

  do {
    /* Get the next parameter. */
    name = ws_get_next_media_type_parameter(p, &namelen, &value, &valuelen, &p);
    if (name == NULL) {
      /* No more parameters - not found. */
      return NULL;
    }

    /* Is it the parameter we're looking for? */
    if (namelen == keylen && g_ascii_strncasecmp(name, key, keylen) == 0) {
      /* Yes. */
      break;
    }
  } while (*p);

  if (value == NULL) {
    /* The parameter doesn't have a value. */
    return NULL;
  }

  /* We found the parameter with that name; now extract the value. */
  // valuestr = (char *)wmem_alloc(scope, valuelen + 1);
  // allocate valuestr using stdlib
  valuestr = (char *)malloc(valuelen + 1);
  vp = valuestr;
  p = value;
  /* Is the value a quoted string? */
  if (*p == '"') {
    /* Yes. Skip the opening quote, and scan forward looking for
       a non-escaped closing quote, copying characters. */
    p++;
    for (;;) {
      c = *p;
      if (c == '\0') {
        /* End-of-string.  We're done.
           (XXX - this is an error.) */
        *vp = '\0';
        return valuestr;
      }
      if (c == '"') {
        /* Closing quote.  Skip it; we're done with
           the quoted-string. */
        p++;
        break;
      }
      if (c == '\\') {
        /* Backslash; this escapes the next character
           (quoted-pair). Skip the backslash, and make
           sure there *is* a next character. */
        p++;
        if (*p == '\0') {
          /* Nothing left; we're done.
             (XXX - this is an error.) */
          break;
        }
      }
      /* Copy the character. */
      *vp++ = *p++;
    }
  } else {
    /* No.  Just scan forward until we see a '\0' (end of
       string or a non-token character, copying characters. */
    while ((c = *p) != '\0' && g_ascii_isgraph(c) && c != '(' && c != ')' &&
           c != '<' && c != '>' && c != '@' && c != ',' && c != ';' &&
           c != ':' && c != '\\' && c != '"' && c != '/' && c != '[' &&
           c != ']' && c != '?' && c != '=' && c != '{' && c != '}') {
      *vp++ = c;
      p++;
    }
  }
  *vp = '\0';
  return valuestr;
}

static multipart_info_t *get_multipart_info(guint8 *content_type_str,
                                            http_message_info_t *message_info) {
  char *start_boundary, *start_protocol = NULL;
  multipart_info_t *m_info = NULL;
  const char *type = (char *)content_type_str;
  const char *parameters = message_info->media_str;

  /*
   * We need both a content type AND parameters
   * for multipart dissection.
   */
  if (type == NULL) {
    return NULL;
  }
  if (message_info == NULL) {
    return NULL;
  }
  if (message_info->media_str == NULL) {
    return NULL;
  }

  start_boundary = ws_find_media_type_parameter(parameters, "boundary");
  if (!start_boundary) {
    return NULL;
  }

  /*
   * There is a value for the boundary string
   */
  m_info = malloc(sizeof(multipart_info_t));
  m_info->type = type;
  m_info->boundary = start_boundary;
  m_info->boundary_length = (guint)strlen(start_boundary);
  if (start_protocol) {
    m_info->protocol = start_protocol;
    m_info->protocol_length = (guint)strlen(start_protocol);
  } else {
    m_info->protocol = NULL;
    m_info->protocol_length = -1;
  }
  m_info->orig_content_type = NULL;
  m_info->orig_parameters = NULL;

  return m_info;
}

/*
 * The first boundary does not implicitly contain the leading
 * line-end sequence.
 *
 * Return the offset to the 1st byte of the boundary delimiter line.
 * Set boundary_line_len to the length of the entire boundary delimiter.
 * Set last_boundary to TRUE if we've seen the last-boundary delimiter.
 */
static gint find_first_boundary(const u_char *tvb, gint tvb_size, gint start,
                                const guint8 *boundary, gint boundary_len,
                                gint *boundary_line_len,
                                gboolean *last_boundary) {
  gint offset = start, next_offset, line_len, boundary_start;

  while (tvb_size > offset + 2 + boundary_len) {
    boundary_start = offset;
    if (((tvb_strneql(tvb, offset, (const guint8 *)"--", 2) == 0) &&
         (tvb_strneql(tvb, offset + 2, boundary, boundary_len) == 0))) {
      /* Boundary string; now check if last */
      if (((tvb_size - (offset + 2 + boundary_len + 2)) >= 0) &&
          (tvb_strneql(tvb, offset + 2 + boundary_len, (const guint8 *)"--",
                       2) == 0)) {
        *last_boundary = TRUE;
      } else {
        *last_boundary = FALSE;
      }
      /* Look for line end of the boundary line */
      line_len = payload_find_line_end(tvb, offset, tvb_size - offset, &offset);
      if (line_len == -1) {
        *boundary_line_len = -1;
      } else {
        *boundary_line_len = offset - boundary_start;
      }
      return boundary_start;
    }
    line_len =
        payload_find_line_end(tvb, offset, tvb_size - offset, &next_offset);
    if (line_len == -1) {
      return -1;
    }
    offset = next_offset;
  }

  return -1;
}

/*
 * Unless the first boundary, subsequent boundaries include a line-end sequence
 * before the dashed boundary string.
 *
 * Return the offset to the 1st byte of the boundary delimiter line.
 * Set boundary_line_len to the length of the entire boundary delimiter.
 * Set last_boundary to TRUE if we've seen the last-boundary delimiter.
 */
static gint find_next_boundary(const u_char *tvb, gint tvb_size, gint start,
                               const guint8 *boundary, gint boundary_len,
                               gint *boundary_line_len,
                               gboolean *last_boundary) {
  gint offset = start, next_offset, line_len, boundary_start;

  while (tvb_size > (offset + 2 + boundary_len)) {
    line_len =
        payload_find_line_end(tvb, offset, tvb_size - offset, &next_offset);
    if (line_len == -1) {
      return -1;
    }
    boundary_start = offset + line_len;
    if (((tvb_strneql(tvb, next_offset, (const guint8 *)"--", 2) == 0) &&
         (tvb_strneql(tvb, next_offset + 2, boundary, boundary_len) == 0))) {
      /* Boundary string; now check if last */
      if (((tvb - (next_offset + 2 + boundary_len + 2)) >= 0) &&
          (tvb_strneql(tvb, next_offset + 2 + boundary_len,
                       (const guint8 *)"--", 2) == 0)) {
        *last_boundary = TRUE;
      } else {
        *last_boundary = FALSE;
      }
      /* Look for line end of the boundary line */
      line_len = payload_find_line_end(tvb, next_offset, tvb_size - next_offset,
                                       &offset);
      if (line_len == -1) {
        *boundary_line_len = -1;
      } else {
        *boundary_line_len = offset - boundary_start;
      }
      return boundary_start;
      /* check if last before CRLF; some ignore the standard, so there is no
       * CRLF before the boundary */
    } else if ((tvb_strneql(tvb, boundary_start - 2, (const guint8 *)"--", 2) ==
                0) &&
               (tvb_strneql(tvb, boundary_start - (2 + boundary_len), boundary,
                            boundary_len) == 0) &&
               (tvb_strneql(tvb, boundary_start - (2 + boundary_len + 2),
                            (const guint8 *)"--", 2) == 0)) {
      boundary_start -= 2 + boundary_len + 2;
      *boundary_line_len = next_offset - boundary_start;
      *last_boundary = TRUE;
      return boundary_start;
    }
    offset = next_offset;
  }

  return -1;
}

/*
 * Process the multipart preamble:
 *      [ preamble line-end ] dashed-boundary transport-padding line-end
 *
 * Return the offset to the start of the first body-part.
 */
static gint process_preamble(const u_char *tvb, gint tvb_size,
                             multipart_info_t *m_info,
                             gboolean *last_boundary) {
  gint boundary_start, boundary_line_len;

  const guint8 *boundary = (guint8 *)m_info->boundary;
  gint boundary_len = m_info->boundary_length;

  boundary_start = find_first_boundary(tvb, tvb_size, 0, boundary, boundary_len,
                                       &boundary_line_len, last_boundary);
  if (boundary_start == 0) {
    return boundary_start + boundary_line_len;
  } else if (boundary_start > 0) {
    if (boundary_line_len > 0) {
      gint body_part_start = boundary_start + boundary_line_len;
      return body_part_start;
    }
  }
  return -1;
}
/*
 * Call this method to actually dissect the multipart body.
 * NOTE - Only do so if a boundary string has been found!
 */
static int dissect_multipart(const u_char *tvb, gint tvb_size,
                             guint8 *content_type_str, void *data) {
  http_message_info_t *message_info = (http_message_info_t *)data;
  multipart_info_t *m_info = get_multipart_info(content_type_str, message_info);
  gint header_start = 0;
  gint body_index = 0;
  gboolean last_boundary = FALSE;

  // print m_info info
  printf("m_info->type: %s\n", m_info->type);
  printf("m_info->boundary: %s\n", m_info->boundary);
  printf("m_info->boundary_length: %d\n", m_info->boundary_length);

  /*
   * Process the multipart preamble
   */
  // header_start = process_preamble(tvb, tvb_size, m_info, &last_boundary);

  gint boundary_line_len, next_boundary_offset, temp_offset = 0;
  next_boundary_offset = find_next_boundary(tvb, tvb_size, 0, m_info->boundary,
                                            m_info->boundary_length,
                                            &boundary_line_len, &last_boundary);
  printf("-------------------------------------Header boundary: %d-------------------------------------\n", next_boundary_offset + boundary_line_len);

  // print string given start offset and length
  printf("%.*s\n", next_boundary_offset - temp_offset , tvb + temp_offset);
  temp_offset = next_boundary_offset + boundary_line_len;


  next_boundary_offset = find_next_boundary(tvb, tvb_size, next_boundary_offset + boundary_line_len, m_info->boundary,
                                            m_info->boundary_length,
                                            &boundary_line_len, &last_boundary);
  printf("-------------------------------------Body boundary: %d-------------------------------------\n", next_boundary_offset + boundary_line_len);

  printf("%.*s\n", next_boundary_offset - temp_offset , tvb + temp_offset);
  temp_offset = next_boundary_offset + boundary_line_len;

  next_boundary_offset = find_next_boundary(tvb, tvb_size, next_boundary_offset + boundary_line_len, m_info->boundary,
                                            m_info->boundary_length,
                                            &boundary_line_len, &last_boundary);
  printf("-------------------------------------Last boundary: %d-------------------------------------\n", next_boundary_offset + boundary_line_len);
  printf("%.*s\n", next_boundary_offset - temp_offset , tvb + temp_offset);
  temp_offset = next_boundary_offset + boundary_line_len;

  return 1;
}
void dissect_imf(const u_char *tvb, size_t tvb_len) {
  guint8 *content_type_str = NULL;
  char *content_encoding_str = NULL;
  guint8 *parameters = NULL;
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
      for (f_info = imf_fields; f_info->name; f_info++) {
        if (strcmp(f_info->name, key) == 0) {
          break;
        }
      }

      hf_id = f_info->hf_id;

      /* value starts immediately after the colon */
      start_offset = end_offset + 1;

      end_offset =
          imf_find_field_end(tvb, start_offset, max_length, &last_field);

      /* remove any leading whitespace */
      for (value_offset = start_offset; value_offset < end_offset;
           value_offset++)
        if (!g_ascii_isspace(*(tvb + value_offset))) {
          break;
        }
      // printf("Key: %s\n", key);
      // // print value with start_offset and end_offset
      // printf("Value: %.*s", end_offset - start_offset,
      //        (const char *)tvb + start_offset);

      if (value_offset == end_offset) {
        /* empty field - show whole value */
        value_offset = start_offset;
      }

      // print key-value pair in pretty table format
      printf("%-30s %.*s", key, end_offset - start_offset,
             (const char *)tvb + start_offset);

      if (hf_id == IMF_FIELD_CONTENT_TYPE) {
        dissect_imf_content_type(tvb, start_offset, end_offset - start_offset,
                                 &content_type_str, &parameters);
        printf("content type: %s, len: %ld\n", content_type_str,
               strlen(content_type_str));
        printf("parameters: %s, len: %ld\n", parameters, strlen(parameters));
      }
    }

    start_offset = end_offset;
  }

  if (last_field) {
    end_offset += 2;
  }
  if (end_offset == -1) {
    end_offset = 0;
  }

  if (TRUE) {

    http_message_info_t message_info;

    if (FALSE) {
    } else {
      next_tvb = (u_char *)tvb + end_offset;
    }

    message_info.type = HTTP_OTHERS;
    message_info.media_str = parameters;
    message_info.data = NULL;
    dissect_multipart(next_tvb, strlen(next_tvb), content_type_str,
                      (void *)&message_info);
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

  print_hashtable(table, fout_list_flow);

  flow_base_t *flow_test = search_flow(table, 6813568831684183325, stdout);
  flow_browser(flow_test);

  printf("\nFreeing...\n");
  free_hash_table(table);
}
