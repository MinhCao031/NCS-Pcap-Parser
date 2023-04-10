#ifndef DISSECT_IMF_H
#define DISSECT_IMF_H

#include "dissect_smtp.h"
#include <glib-2.0/glib.h>
// #include <glib-2.0/glibconfig.h>

#include "ws/wsutil/str_util.h"
#define PNAME "Internet Message Format"
#define PSNAME "IMF"
#define PFNAME "imf"

#define NO_SUBDISSECTION NULL

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
  const char *name; /* field name - in lower case for matching purposes */
  enum field hf_id; /* wireshark field */
  void (*subdissector)(tvbuff_t *tvb, int offset, int length);
};

// find index if charactor in string
static int tvb_find_char(tvbuff_t *tvb, const gint start_offset,
                         const gint max_length, const guint8 needle) {

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
    result =
        (const guint8 *)memchr(tvb->real_data + start_offset, needle, limit);
    if (result == NULL) {
      return -1;
    } else {
      return (gint)(result - tvb->real_data);
    }
  }
  return -1;
}
static void dissect_imf_mailbox(tvbuff_t *tvb, gint offset, gint length) {

  int addr_pos, end_pos;

  /* Here is the plan:
     If we can't find and angle brackets, then the whole field is an address.
     If we find angle brackets, then the address is between them and the display
     name is anything before the opening angle bracket
  */

  if ((addr_pos = tvb_find_char(tvb, offset, length, '<')) == -1) {
    /* we can't find an angle bracket - the whole field is therefore the address
     */

    printf("\taddress: %.*s\n", length, tvb->real_data + offset);

  } else {
    /* we can find an angle bracket - let's see if we can find a display name */
    /* XXX: the '<' could be in the display name */

    for (; offset < addr_pos; offset++) {
      if (!g_ascii_isspace(*(tvb->real_data + offset))) {
        break;
      }
    }

    end_pos =
        tvb_find_char(tvb, addr_pos + 1, length - (addr_pos + 1 - offset), '>');

    // print address string with length
    printf("\taddress: %.*s\n", end_pos - addr_pos - 1,
           tvb->real_data + addr_pos + 1);
  }
};
static void dissect_imf_address(tvbuff_t *tvb, int offset, gint length) {

  int addr_pos;

  /* if there is a colon present it is a group */
  if ((addr_pos = tvb_find_char(tvb, offset, length, ':')) == -1) {

    /* there isn't - so it must be a mailbox */
    dissect_imf_mailbox(tvb, offset, length);

  } else {

    /* consume any whitespace */
    for (addr_pos++; addr_pos < (offset + length); addr_pos++) {
      if (!g_ascii_isspace(*(tvb->real_data + addr_pos))) {
        break;
      }
    }

    if (*(tvb->real_data + addr_pos) != ';') {

      // dissect_imf_mailbox_list(tvb, addr_pos, length - (addr_pos - offset));

      /* XXX: need to check for final ';' */
    }
  }
};
static void dissect_imf_address_list(tvbuff_t *tvb, int offset, gint length) {

  int count = 0;
  int item_offset;
  int end_offset;
  int item_length;

  item_offset = offset;

  do {

    end_offset =
        tvb_find_char(tvb, item_offset, length - (item_offset - offset), ',');

    count++; /* increase the number of items */

    if (end_offset == -1) {
      /* length is to the end of the buffer */
      item_length = length - (item_offset - offset);
    } else {
      item_length = end_offset - item_offset;
    }
    // addr_item = proto_tree_add_item(tree, hf_imf_address_list_item, tvb,
    // item_offset, item_length, ENC_ASCII|ENC_NA);
    dissect_imf_address(tvb, item_offset, item_length);

    if (end_offset != -1) {
      item_offset = end_offset + 1;
    }
  } while (end_offset != -1);

  // /* now indicate the number of items found */
  // proto_item_append_text(item, ", %d item%s", count, plurality(count, "",
  // "s"));
}
static void dissect_imf_mailbox_list(tvbuff_t *tvb, int offset, gint length) {

  int count = 0;
  int item_offset;
  int end_offset;
  int item_length;

  item_offset = offset;

  do {

    end_offset =
        tvb_find_char(tvb, item_offset, length - (item_offset - offset), ',');

    count++; /* increase the number of items */

    if (end_offset == -1) {
      /* length is to the end of the buffer */
      item_length = length - (item_offset - offset);
    } else {
      item_length = end_offset - item_offset;
    }
    dissect_imf_mailbox(tvb, item_offset, item_length);

    if (end_offset != -1) {
      item_offset = end_offset + 1;
    }
  } while (end_offset != -1);
};
static void dissect_imf_siolabel(){};

static struct imf_field imf_fields[] = {

    {"unkown-extension", IMF_FIELD_UNKNOWN, NO_SUBDISSECTION},
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
    {"mime-version", IMF_FIELD_MIME_VERSION, NO_SUBDISSECTION},
    {"date", IMF_FIELD_DATE, NO_SUBDISSECTION},
    {"user-agent", IMF_FIELD_USER_AGENT, NO_SUBDISSECTION},
    {"content-language", IMF_FIELD_CONTENT_LANGUAGE, NO_SUBDISSECTION},
    {NULL, NOPE, NULL}};

int imf_find_field_end(tvbuff_t *tvb, int offset, gint max_length,
                       gboolean *last_field) {

  while (offset < max_length) {

    /* look for CR */
    offset = tvb_find_char(tvb, offset, max_length - offset, '\r');

    if (offset != -1) {
      /* protect against buffer overrun and only then look for next char */
      if (++offset < max_length && *(tvb->real_data + offset) == '\n') {
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
        switch (*(tvb->real_data + offset)) {
        case '\r':
          /* probably end of the fields */
          if ((offset + 1) < max_length &&
              *(tvb->real_data + offset + 1) == '\n') {
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

static void dissect_imf_content_type(tvbuff_t *tvb, int offset, int length,
                                     guint8 **type, guint8 **parameters) {
  int first_colon;
  int end_offset;
  int len;
  int i;

  /* first strip any whitespace */
  for (i = 0; i < length; i++) {
    if (!g_ascii_isspace(*(tvb->real_data + offset + i))) {
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
    // memcpy((void *)*type, tvb + offset, len);
    // using g_memdup instead of memcpy
    *type = (guint8 *)g_memdup2(tvb->real_data + offset, len);

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
    // memcpy((void *)*parameters, tvb + first_colon + 1, len);
    // using g_memdup instead of memcpy
    *parameters = (guint8 *)g_memdup2(tvb->real_data + first_colon + 1, len);
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
  m_info = (multipart_info_t *)malloc(sizeof(multipart_info_t));
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
static gint find_first_boundary(tvbuff_t *tvb, gint start,
                                const guint8 *boundary, gint boundary_len,
                                gint *boundary_line_len,
                                gboolean *last_boundary) {
  gint offset = start, next_offset, line_len, boundary_start;

  while (tvb_offset_exists(tvb, offset + 2 + boundary_len)) {
    boundary_start = offset;
    if (((tvb_strneql(tvb, offset, (const gchar *)"--", 2) == 0) &&
         (tvb_strneql(tvb, offset + 2, (const gchar *)boundary, boundary_len) ==
          0))) {
      /* Boundary string; now check if last */
      if (tvb_length_remaining(tvb, (offset + 2 + boundary_len + 2) >= 0) &&
          (tvb_strneql(tvb, offset + 2 + boundary_len, (const gchar *)"--",
                       2) == 0)) {
        *last_boundary = TRUE;
      } else {
        *last_boundary = FALSE;
      }
      /* Look for line end of the boundary line */
      line_len =
          payload_find_line_end(tvb, offset, tvb->length - offset, &offset);
      if (line_len == -1) {
        *boundary_line_len = -1;
      } else {
        *boundary_line_len = offset - boundary_start;
      }
      return boundary_start;
    }
    line_len =
        payload_find_line_end(tvb, offset, tvb->length - offset, &next_offset);
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
static gint find_next_boundary(tvbuff_t *tvb, gint start,
                               const guint8 *boundary, gint boundary_len,
                               gint *boundary_line_len,
                               gboolean *last_boundary) {
  gint offset = start, next_offset, line_len, boundary_start;

  while (tvb_offset_exists(tvb, (offset + 2 + boundary_len))) {
    line_len =
        payload_find_line_end(tvb, offset, tvb->length - offset, &next_offset);
    if (line_len == -1) {
      return -1;
    }
    boundary_start = offset + line_len;
    if (((tvb_strneql(tvb, next_offset, (const gchar *)"--", 2) == 0) &&
         (tvb_strneql(tvb, next_offset + 2, (const gchar *)boundary,
                      boundary_len) == 0))) {
      /* Boundary string; now check if last */
      if (tvb_length_remaining(tvb,
                               (next_offset + 2 + boundary_len + 2) >= 0) &&
          (tvb_strneql(tvb, next_offset + 2 + boundary_len, (const gchar *)"--",
                       2) == 0)) {
        *last_boundary = TRUE;
      } else {
        *last_boundary = FALSE;
      }
      /* Look for line end of the boundary line */
      line_len = payload_find_line_end(tvb, next_offset,
                                       tvb->length - next_offset, &offset);
      if (line_len == -1) {
        *boundary_line_len = -1;
      } else {
        *boundary_line_len = offset - boundary_start;
      }
      return boundary_start;
      /* check if last before CRLF; some ignore the standard, so there is no
       * CRLF before the boundary */
    } else if ((tvb_strneql(tvb, boundary_start - 2, (const gchar *)"--", 2) ==
                0) &&
               (tvb_strneql(tvb, boundary_start - (2 + boundary_len),
                            (const gchar *)boundary, boundary_len) == 0) &&
               (tvb_strneql(tvb, boundary_start - (2 + boundary_len + 2),
                            (const gchar *)"--", 2) == 0)) {
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
static gint process_preamble(tvbuff_t *tvb, multipart_info_t *m_info,
                             gboolean *last_boundary) {
  gint boundary_start, boundary_line_len;

  const guint8 *boundary = (guint8 *)m_info->boundary;
  gint boundary_len = m_info->boundary_length;

  boundary_start = find_first_boundary(tvb, 0, boundary, boundary_len,
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
 * Unfold and clean up a MIME-like header, and process LWS as follows:
 *      o Preserves LWS in quoted text
 *      o Remove LWS before and after a separator
 *      o Remove trailing LWS
 *      o Replace other LWS with a single space
 * Set value to the start of the value
 * Return the cleaned-up RFC2822 header (buffer must be freed).
 */
static char *unfold_and_compact_mime_header(const char *lines,
                                            gint *first_colon_offset) {
  const char *p = lines;
  char c;
  char *ret, *q;
  char sep_seen = 0; /* Did we see a separator ":;," */
  char lws = FALSE;  /* Did we see LWS (incl. folding) */
  gint colon = -1;

  if (!lines)
    return NULL;

  c = *p;
  ret = (char *)malloc(strlen(lines) + 1);
  q = ret;

  while (c) {
    if (c == ':') {
      lws = FALSE;       /* Prevent leading LWS from showing up */
      if (colon == -1) { /* First colon */
        colon = (gint)(q - ret);
      }
      *(q++) = sep_seen = c;
      p++;
    } else if (c == ';' || c == ',' || c == '=') {
      lws = FALSE; /* Prevent leading LWS from showing up */
      *(q++) = sep_seen = c;
      p++;
    } else if (c == ' ' || c == '\t') {
      lws = TRUE;
      p++;
    } else if (c == '\n') {
      lws = FALSE; /* Skip trailing LWS */
      if ((c = *(p + 1))) {
        if (c == ' ' || c == '\t') { /* Header unfolding */
          lws = TRUE;
          p += 2;
        } else {
          *q = c = 0; /* Stop */
        }
      }
    } else if (c == '\r') {
      lws = FALSE;
      if ((c = *(p + 1))) {
        if (c == '\n') {
          if ((c = *(p + 2))) {
            if (c == ' ' || c == '\t') { /* Header unfolding */
              lws = TRUE;
              p += 3;
            } else {
              *q = c = 0; /* Stop */
            }
          }
        } else if (c == ' ' || c == '\t') { /* Header unfolding */
          lws = TRUE;
          p += 2;
        } else {
          *q = c = 0; /* Stop */
        }
      }
    } else if (c == '"') { /* Start of quoted-string */
      lws = FALSE;
      *(q++) = c;
      while (c) {
        c = *(q++) = *(++p);
        if (c == '\\') {
          /* First part of a quoted-pair; copy the other part,
             without checking if it's a quote */
          c = *(q++) = *(++p);
        } else {
          if (c == '"') {
            p++; /* Skip closing quote */
            break;
          }
        }
      }
      /* if already zero terminated now, rewind one char to avoid an "off by
       * one" */
      if (c == 0) {
        q--;
      }
    } else { /* Regular character */
      if (sep_seen) {
        sep_seen = 0;
      } else {
        if (lws) {
          *(q++) = ' ';
        }
      }
      lws = FALSE;
      *(q++) = c;
      p++; /* OK */
    }

    if (c) {
      c = *p;
    }
  }
  *q = 0;

  *first_colon_offset = colon;
  return (ret);
}

/* Not sure that compact_name exists for multipart, but choose to keep
 * the structure from SIP dissector, all the content- is also from SIP */

typedef struct {
  const char *name;
  const char *compact_name;
} multipart_header_t;

static const multipart_header_t multipart_headers[] = {
    {"Unknown-header",
     NULL}, /* Pad so that the real headers start at index 1 */
    {"Content-Description", NULL},
    {"Content-Disposition", NULL},
    {"Content-Encoding", "e"},
    {"Content-Id", NULL},
    {"Content-Language", NULL},
    {"Content-Length", "l"},
    {"Content-Transfer-Encoding", NULL},
    {"Content-Type", "c"},
    {"OriginalContent", NULL}};

#define POS_CONTENT_DESCRIPTION 1
#define POS_CONTENT_DISPOSITION 2
#define POS_CONTENT_ENCODING 3
#define POS_CONTENT_ID 4
#define POS_CONTENT_LANGUAGE 5
#define POS_CONTENT_LENGTH 6
#define POS_CONTENT_TRANSFER_ENCODING 7
#define POS_CONTENT_TYPE 8
#define POS_ORIGINALCONTENT 9

/* Useful when you have an array whose size you can tell at compile-time */
#define array_length(x) (sizeof x / sizeof x[0])

static gboolean remove_base64_encoding = FALSE;
/* Returns index of method in multipart_headers */
static gint is_known_multipart_header(const char *header_str, guint len) {
  guint i;

  for (i = 1; i < array_length(multipart_headers); i++) {
    if (len == strlen(multipart_headers[i].name) &&
        g_ascii_strncasecmp(header_str, multipart_headers[i].name, len) == 0)
      return i;
    if (multipart_headers[i].compact_name != NULL &&
        len == strlen(multipart_headers[i].compact_name) &&
        g_ascii_strncasecmp(header_str, multipart_headers[i].compact_name,
                            len) == 0)
      return i;
  }

  return -1;
}

static int dissect_text_lines(tvbuff_t *tvb, guint8 *content_type_str,
                              void *data) {
  gint offset = 0, next_offset;
  gint len;
  http_message_info_t *message_info;
  const char *data_name;
  int length = tvb->length;

  /* Check if this is actually xml
   * If there is less than 38 characters this is not XML
   * <?xml version="1.0" encoding="UTF-8"?>
   */
  if (length > 38) {
    // if (tvb_strncaseeql(tvb, 0, "<?xml", 5) == 0){
    // 	call_dissector(xml_handle, tvb, pinfo, tree);
    // 	return length;
    // }
  }

  data_name = (char *)content_type_str;
  if (!(data_name && data_name[0])) {
    /*
     * No information from "match_string"
     */
    message_info = (http_message_info_t *)data;
    if (message_info == NULL) {
      /*
       * No information from dissector data
       */
      data_name = NULL;
    } else {
      data_name = message_info->media_str;
      if (!(data_name && data_name[0])) {
        /*
         * No information from dissector data
         */
        data_name = NULL;
      }
    }
  }

  return length;
}
static int dissect_multipart(tvbuff_t *tvb, guint8 *content_type_str,
                             void *data);
/*
 * Process a multipart body-part:
 *      MIME-part-headers [ line-end *OCTET ]
 *      line-end dashed-boundary transport-padding line-end
 *
 * If applicable, call a media subdissector.
 *
 * Return the offset to the start of the next body-part.
 */

static gint process_body_part(tvbuff_t *tvb,
                              http_message_info_t *input_message_info,
                              multipart_info_t *m_info, gint start, gint idx,
                              gboolean *last_boundary)

{
  gint offset = start, next_offset = 0;
  http_message_info_t message_info = {input_message_info->type, NULL, NULL,
                                      NULL};
  gint body_start, boundary_start, boundary_line_len;
  gchar *content_type_str = NULL;
  gchar *content_trans_encoding_str = NULL;

  char *filename = NULL;
  char *mimetypename = NULL;
  gboolean last_field = FALSE;
  gboolean is_raw_data = FALSE;

  const guint8 *boundary = (guint8 *)m_info->boundary;
  gint boundary_len = m_info->boundary_length;

  /* find the next boundary to find the end of this body part */
  boundary_start = find_next_boundary(tvb, offset, boundary, boundary_len,
                                      &boundary_line_len, last_boundary);

  if (boundary_start <= 0) {
    return -1;
  }

  /*
   * Process the MIME-part-headers
   */

  if (boundary_start <= 0) {
    return -1;
  }

  /*
   * Process the MIME-part-headers
   */

  while (!last_field) {
    gint colon_offset;
    char *hdr_str;
    char *header_str;

    /* Look for the end of the header (denoted by cr)
     * 3:d argument to imf_find_field_end() maxlen; must be last offset in the
     * tvb.
     */
    next_offset = imf_find_field_end(
        tvb, offset, (tvb->length - offset) + offset, &last_field);

    /* the following should never happen */
    /* If cr not found, won't have advanced - get out to avoid infinite loop! */
    /*
    if (next_offset == offset) {
        break;
    }
    */
    if (last_field && (next_offset + 2) <= boundary_start) {
      /* Add the extra CRLF of the last field */
      next_offset += 2;
    } else if ((next_offset - 2) == boundary_start) {
      /* if CRLF is the start of next boundary it belongs to the boundary and
         not the field, so it's the last field without CRLF */
      last_field = TRUE;
      next_offset -= 2;
    } else if (next_offset > boundary_start) {
      /* if there is no CRLF between last field and next boundary - trim it! */
      next_offset = boundary_start;
    }

    // hdr_str = tvb_get_string_enc(pinfo->pool, tvb, offset, next_offset -
    // offset, ENC_ASCII);
    hdr_str = (char *)g_memdup2(tvb->real_data + offset, next_offset - offset);

    colon_offset = 0;
    header_str = unfold_and_compact_mime_header(hdr_str, &colon_offset);
    if (colon_offset <= 0) {
      /* if there is no colon it's no header, so break and add complete line to
       * the body */
      next_offset = offset;
      break;
    } else {
      gint hf_index;

      hf_index = is_known_multipart_header(header_str, colon_offset);

      if (hf_index == -1) {
        if (isprint_string(header_str)) {
        } else {
          /* if the header name is unknown and not printable, break and add
           * complete line to the body */
          next_offset = offset;
          break;
        }
      } else {
        char *value_str =
            // wmem_strdup(pinfo->pool, header_str + colon_offset + 1);
            // using g_memdup2 instead of wmem_strdup
            (char *)g_memdup2(header_str + colon_offset + 1,
                              strlen(header_str + colon_offset + 1));

        switch (hf_index) {
        case POS_ORIGINALCONTENT: {
          char *semicolonp;
          /* The Content-Type starts at colon_offset + 1 or after the type
           * parameter */
          char *type_str = ws_find_media_type_parameter(value_str, "type");
          if (type_str != NULL) {
            value_str = type_str;
          }

          semicolonp = strchr(value_str, ';');

          if (semicolonp != NULL) {
            *semicolonp = '\0';
            m_info->orig_parameters =
                (char *)g_memdup2(semicolonp + 1, strlen(semicolonp + 1));
          }

          m_info->orig_content_type = ascii_strdown_inplace(value_str);
        } break;
        case POS_CONTENT_TYPE: {
          /* The Content-Type starts at colon_offset + 1 */
          char *semicolonp = strchr(value_str, ';');

          if (semicolonp != NULL) {
            *semicolonp = '\0';
            // using g_memdup2 instead of wmem_strdup
            message_info.media_str =
                (char *)g_memdup2(semicolonp + 1, strlen(semicolonp + 1));
          } else {
            message_info.media_str = NULL;
          }

          content_type_str = ascii_strdown_inplace(value_str);
          printf("content_type_str: %s\n", content_type_str);

          /* find the "name" parameter in case we don't find a content
           * disposition "filename" */
          mimetypename =
              ws_find_media_type_parameter(message_info.media_str, "name");
          printf("mimetypename: %s\n", mimetypename);

          if (strncmp(content_type_str, "application/octet-stream",
                      sizeof("application/octet-stream") - 1) == 0) {
            is_raw_data = TRUE;
          }

          /* there are only 2 body parts possible and each part has specific
           * content types */
          if (m_info->protocol && idx == 0 &&
              (is_raw_data ||
               g_ascii_strncasecmp(content_type_str, m_info->protocol,
                                   strlen(m_info->protocol)) != 0)) {
            return -1;
          }
        } break;
        case POS_CONTENT_ENCODING: {
          /* The Content-Encoding starts at colon_offset + 1 */
          char *crp = strchr(value_str, '\r');

          if (crp != NULL) {
            *crp = '\0';
          }

        } break;
        case POS_CONTENT_TRANSFER_ENCODING: {
          /* The Content-Transferring starts at colon_offset + 1 */
          char *crp = strchr(value_str, '\r');

          if (crp != NULL) {
            *crp = '\0';
          }

          content_trans_encoding_str = ascii_strdown_inplace(value_str);
          printf("Content transfer encoding: %s\n", content_trans_encoding_str);
        } break;
        case POS_CONTENT_DISPOSITION: {
          /* find the "filename" parameter */
          filename = ws_find_media_type_parameter(value_str, "filename");
          printf("filename: %s\n", filename);
        } break;
        case POS_CONTENT_ID:
          // use g_memdup2 instead of wmem_strdup
          message_info.content_id =
              (char *)g_memdup2(value_str, strlen(value_str));
          break;
        default:
          break;
        }
        // g_free(value_str);
        // g_free(header_str);
        // g_free(hdr_str);
      }
    }
    offset = next_offset;
  }

  body_start = next_offset;

  /*
   * Process the body
   */

  {
    gint body_len = boundary_start - body_start;
    // tvbuff_t *tmp_tvb = tvb_new_subset_length(tvb, body_start, body_len);

    tvbuff_t *tmp_tvb = (tvbuff_t *)g_malloc(sizeof(tvbuff_t));
    tmp_tvb->real_data =
        (guint8 *)g_memdup2(tvb->real_data + body_start, body_len),
    tmp_tvb->length = (guint)body_len;
    /*
     * If multipart subtype is encrypted the protcol string was set.
     *
     * See MS-WSMV section 2.2.9.1.2.1 "HTTP Headers":
     *
     *
     https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wsmv/b79927c2-96be-4801-aa68-180db95593f9
     *
     * There are only 2 body parts possible, and each part has specific
     * content types.
     */
    // if(m_info->protocol && idx == 1 && is_raw_data)
    // {
    //     gssapi_encrypt_info_t  encrypt;

    //     memset(&encrypt, 0, sizeof(encrypt));
    //     encrypt.decrypt_gssapi_tvb=DECRYPT_GSSAPI_NORMAL;

    //     dissect_kerberos_encrypted_message(tmp_tvb, pinfo, subtree,
    //     &encrypt);

    //     if(encrypt.gssapi_decrypted_tvb){
    //             tmp_tvb = encrypt.gssapi_decrypted_tvb;
    //             is_raw_data = FALSE;
    //             content_type_str = m_info->orig_content_type;
    //             message_info.media_str = m_info->orig_parameters;
    //     } else if(encrypt.gssapi_encrypted_tvb) {
    //             tmp_tvb = encrypt.gssapi_encrypted_tvb;
    //             proto_tree_add_expert(tree, pinfo,
    //             &ei_multipart_decryption_not_possible, tmp_tvb, 0, -1);
    //     }
    // }

    if (!is_raw_data && content_type_str) {

      /*
       * subdissection
       */
      gboolean dissected;

      /*
       * Try and remove any content transfer encoding so that each
       sub-dissector
       * doesn't have to do it itself
       *
       */

      if (content_trans_encoding_str && remove_base64_encoding) {

        // if(!g_ascii_strncasecmp(content_trans_encoding_str, "base64",
        // 6))
        //     tmp_tvb = base64_decode(pinfo, tmp_tvb, filename ?
        //     filename : (mimetypename ? mimetypename :
        //     content_type_str));
      }

      /*
       * First try the dedicated multipart dissector table
       */

      if (strcmp(content_type_str, "text/plain") == 0) {
        dissected = dissect_text_lines(tmp_tvb, (guint8 *)content_type_str,
                                       &message_info);
        // return 0;
      }

      if (strcmp(content_type_str, "text/html") == 0) {
        dissected = dissect_text_lines(tmp_tvb, (guint8 *)content_type_str,
                                       &message_info);
        // return 0;
      }

      if (strcmp(content_type_str, "multipart/alternative") == 0) {
        dissected = dissect_multipart(tmp_tvb, (guint8 *)content_type_str,
                                      &message_info);
        // return 0;
      }
      // dissected =
      // dissector_try_string(multipart_media_subdissector_table,
      //             content_type_str, tmp_tvb, pinfo, subtree,
      //             &message_info);
      // if (! dissected) {
      //     /*
      //      * Fall back to the default media dissector table
      //      */
      //     dissected = dissector_try_string(media_type_dissector_table,
      //             content_type_str, tmp_tvb, pinfo, subtree,
      //             &message_info);
      // }
      // if (! dissected) {
      //     const char *save_match_string = pinfo->match_string;
      //     pinfo->match_string = content_type_str;
      //     call_dissector_with_data(media_handle, tmp_tvb, pinfo,
      //     subtree, &message_info); pinfo->match_string =
      //     save_match_string;
      // }
      // message_info.media_str = NULL; /* Shares same memory as
      // content_type_str */
    }
    // else {
    //         call_data_dissector(tmp_tvb, pinfo, subtree);
    //     }
    //     proto_item_set_len(ti, boundary_start - start);
    //     if (*last_boundary == TRUE) {
    //        proto_tree_add_item(tree, hf_multipart_last_boundary, tvb,
    //        boundary_start, boundary_line_len, ENC_NA|ENC_ASCII);
    //     } else {
    //        proto_tree_add_item(tree, hf_multipart_boundary, tvb,
    //        boundary_start, boundary_line_len, ENC_NA|ENC_ASCII);
    //     }

    // free the memory allocated for the tmp_tvb

    // g_free((void *)tmp_tvb->real_data);
    // g_free(tmp_tvb);

    return boundary_start + boundary_line_len;
  }
}

/*
 * Call this method to actually dissect the multipart body.
 * NOTE - Only do so if a boundary string has been found!
 */
static int dissect_multipart(tvbuff_t *tvb, guint8 *content_type_str,
                             void *data) {
  http_message_info_t *message_info = (http_message_info_t *)data;
  multipart_info_t *m_info = get_multipart_info(content_type_str, message_info);
  gboolean last_boundary = FALSE;

  printf("==================================== MIME "
         "====================================\n");
  // print m_info info
  printf("m_info->type: %s\n", m_info->type);
  printf("m_info->boundary: %s\n", m_info->boundary);

  /*
   * Process the multipart preamble
   */
  gint header_start = process_preamble(tvb, m_info, &last_boundary);

  gint body_index = 0;

  /*
   * Process the encapsulated bodies
   */
  while (last_boundary == FALSE) {
    printf("------------------------------------ boundary "
           "------------------------------------\n");
    header_start = process_body_part(tvb, message_info, m_info, header_start,
                                     body_index++, &last_boundary);
  }

  printf("------------------------------------ last boundary "
         "------------------------------------\n");
  return tvb->length;
}
void dissect_imf(tvbuff_t *tvb) {
  guint8 *content_type_str = NULL;
  guint8 *parameters = NULL;
  int hf_id;
  gint start_offset = 0;
  gint value_offset = 0;
  gint end_offset = 0;
  gint max_length;
  gchar *key;
  gboolean last_field = FALSE;
  tvbuff_t *next_tvb;
  struct imf_field *f_info;

  max_length = tvb->length;

  while (!last_field) {

    // look for a colon first
    end_offset = tvb_find_char(tvb, start_offset, max_length, ':');

    if (end_offset == -1) {
      // no colon found, so this is not a valid header
      break;
    } else {
      key = g_strndup((const char *)tvb->real_data + start_offset,
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
        if (!g_ascii_isspace(*(tvb->real_data + value_offset))) {
          break;
        }

      if (value_offset == end_offset) {
        /* empty field - show whole value */
        value_offset = start_offset;
      }

      // print key-value pair in pretty table format
      printf("%-30s %.*s", key, end_offset - start_offset,
             (const char *)tvb->real_data + start_offset);

      if (hf_id == IMF_FIELD_CONTENT_TYPE) {
        dissect_imf_content_type(tvb, start_offset, end_offset - start_offset,
                                 &content_type_str, &parameters);
        printf("content type: %s, len: %ld\n", content_type_str,
               strlen((const char *)content_type_str));
        printf("parameters: %s, len: %ld\n", parameters,
               strlen((const char *)parameters));
      } else if (f_info->subdissector) {
        f_info->subdissector(tvb, value_offset, end_offset - value_offset);
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
      next_tvb->real_data = tvb->real_data + end_offset;
      next_tvb->length = tvb->length - end_offset;
    } else {
      next_tvb = (tvbuff_t *)malloc(sizeof(tvbuff_t));
      next_tvb->real_data = tvb->real_data + end_offset;
      next_tvb->length = tvb->length - end_offset;
    }

    message_info.type = HTTP_OTHERS;
    message_info.media_str = (const char *)parameters;
    message_info.data = NULL;
    dissect_multipart(next_tvb, content_type_str, (void *)&message_info);
  }
  // g_free(content_type_str);
  // g_free(parameters);
}

#endif
