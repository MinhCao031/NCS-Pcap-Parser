#ifndef LOG_H
#define LOG_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <glib.h>

#include <pcap.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#pragma once

/* These below are just for debug */
extern const guint8 *DBG_TIMER;
extern const guint8 *DBG_PARSER;
extern const guint8 *DBG_FLOW;
extern const guint8 *DBG_PAYLOAD;
extern const guint8 *DBG_CONSOLE;
extern const guint8 *DBG_DISSECT;

extern FILE *LOG_PARSE;
extern FILE *LOG_FLOWS;
extern FILE *LOG_DISEC;

#define SEC2NANO 1000000000
#define LIMIT_PACKET 2700000
#define POW2(p) (size_t)(1ULL << p)

// If a sequence is too far from the previous one, that packet is consider ignored
#define MAX_BYTE_DISTANCE pow2(29)

// Some txt file to print when debugging
#define FILE_PARSE "output_parse_packet.txt"
#define FILE_FLOWS "output_wireshark.txt"
#define FILE_DISEC "output_dissect_pkt.txt"

#define HAS_FIN_FLAG (pkt.tcp.th_flags & TH_FIN)
#define HAS_SYN_FLAG (pkt.tcp.th_flags & TH_SYN)
#define HAS_RST_FLAG (pkt.tcp.th_flags & TH_RST)
#define HAS_PSH_FLAG (pkt.tcp.th_flags & TH_PUSH)
#define HAS_ACK_FLAG (pkt.tcp.th_flags & TH_ACK)

#define HAS_FIN_ONLY (pkt.tcp.th_flags == 0x001)
#define HAS_SYN_ONLY (pkt.tcp.th_flags == 0x002)
#define HAS_RST_ONLY (pkt.tcp.th_flags == 0x004)
#define HAS_PSH_ONLY (pkt.tcp.th_flags == 0x008)
#define HAS_ACK_ONLY (pkt.tcp.th_flags == 0x010)

// Format for printing debug info
#define LOG_DBG(stream, print, format, others...) \
  if (stream && print)                            \
  {                                               \
    fprintf(stream, format, ##others);            \
    fflush(stream);                               \
  } else {}

#define LOG_SCR(format, others...) \
  if (*DBG_CONSOLE)                \
    printf(format, ##others);      \
  else {}

// Argument parser
#define ARG_PARSING                                                       \
  do                                                                      \
  {                                                                       \
    if (argc < 2)                                                         \
    {                                                                     \
      printf("Error: Name of pcap must be included as last argument.\n"); \
      exit(11);                                                           \
    }                                                                     \
    FILE_PCAP = argv[argc - 1];                                           \
    printf("File: \'%s\'\n\n", FILE_PCAP);                                \
    int arg_parser = parse_arg(argc, argv);                               \
    printf("Parser result = %d\n", arg_parser);                           \
    if (arg_parser < 1)                                                   \
    {                                                                     \
      printf("No debug mode?\n");                                         \
    }                                                                     \
    FILE *fp = fopen(FILE_PCAP, "rb");                                    \
    if (fp == NULL)                                                       \
    {                                                                     \
      printf("Error opening file\n");                                     \
      exit(13);                                                           \
    }                                                                     \
    fseek(fp, 0L, SEEK_END);                                              \
    pcap_file_size = ftell(fp);                                           \
    printf("Size of file: %ld bytes\n\n", pcap_file_size);                \
    fclose(fp);                                                           \
  } while (0)

// Get full timestamp
#define GET_FULL_TIMESTAMP                                \
  char full_timestamp[80];                                \
  struct tm ts = *localtime(&((header_pcap->ts).tv_sec)); \
  strftime(full_timestamp, sizeof(full_timestamp), "%a %Y-%m-%d %H:%M:%S %Z", &ts);

#define PROCESS_PACKET_TIME(time_limit_warning)                    \
  if (*DBG_TIMER)                                                  \
  {                                                                \
    process_time = (pkt_end.tv_sec - pkt_start.tv_sec) * SEC2NANO; \
    process_time += pkt_end.tv_nsec - pkt_start.tv_nsec;           \
    process_time_total += process_time;                            \
    if (process_time < 1001)                                       \
      sttstc[process_time / 100 - 3] += 1;                         \
    else if (process_time < 10001)                                 \
      sttstc[6 + (process_time + 999) / 1000] += 1;                \
    else if (process_time < 100001)                                \
      sttstc[15 + (process_time + 9999) / 10000] += 1;             \
    else                                                           \
      sttstc[26] += 1;                                             \
    LOG_DBG(fout_parser, (process_time > time_limit_warning),      \
            "Packet%8u:%7lu nsec (%d/6)\n",                        \
            captured_packets, process_time, progress_pkt);         \
  }

#define STATISTIC_PACKET_TIME                                                                            \
  if (*DBG_TIMER)                                                                                        \
  {                                                                                                      \
    LOG_DBG(fout_parser, 1, "Packet time total: %lu\n", process_time_total);                             \
    LOG_DBG(fout_parser, 1, "Average time process: %lf\n", 1.0 * process_time_total / captured_packets); \
    for (guint8 i = 0; i < 8; i++)                                                                       \
      LOG_DBG(fout_parser, 1, " =%-6u nsec: %7u time(s)\n", (i + 3) * 100, sttstc[i]);                   \
    for (guint8 i = 8; i < 17; i++)                                                                      \
      LOG_DBG(fout_parser, 1, "<=%-6u nsec: %7u time(s)\n", (i - 6) * 1000, sttstc[i]);                  \
    for (guint8 i = 17; i < 26; i++)                                                                     \
      LOG_DBG(fout_parser, 1, "<=%-6u nsec: %7u time(s)\n", (i - 15) * 10000, sttstc[i]);                \
    LOG_DBG(fout_parser, 1, "> 100000 nsec: %7u time(s)\n", sttstc[26]);                                 \
  }

// Try to insert to flow
#define TRY_INSERT_FLOW                                                                   \
  do                                                                                      \
  {                                                                                       \
    guint8 direction = is_packet_up(flow, pkt);                                           \
    guint32 expect_seq = flow->next_seq[direction];                                       \
    guint32 currnt_seq = pkt.tcp.seq;                                                     \
    guint32 currnt_len = pkt.payload.data_len;                                            \
    if (currnt_seq + currnt_len <= expect_seq)                                            \
    {                                                                                     \
      LOG_DBG(stream, *DBG_PARSER,                                                        \
              "TCP not inserted: SEQ(%u <= %u <= %u) -> Payload already in flow\n",       \
              currnt_seq, expect_seq, currnt_seq + currnt_len);                           \
    }                                                                                     \
    else if (currnt_seq <= expect_seq)                                                    \
    {                                                                                     \
      LOG_DBG(stream, *DBG_PARSER, "TCP inserted: New payload: SEQ(%u <= %u <= %u)\n",    \
              currnt_seq, expect_seq, currnt_seq + currnt_len);                           \
      Node *new_pkt_node = create_payload_node(pkt, direction, expect_seq - currnt_seq);  \
      flow->next_seq[direction] = currnt_seq + currnt_len;                                \
      flow->total_payload += currnt_seq + currnt_len - expect_seq;                        \
      insert_to_flow(new_pkt_node, ASC, flow, stream);                                    \
      /* handle_ftp_pkt(flow, new_pkt_node, stream); */                                   \
      if (currnt_seq == expect_seq)                                                       \
        flow->track_flow[direction] = new_pkt_node;                                       \
      inserted_packets += 1;                                                              \
    }                                                                                     \
    else                                                                                  \
    {                                                                                     \
      LOG_DBG(stream, *DBG_PARSER,                                                        \
              "TCP may not be inserted: SEQ(%u <= %u <= %u) -> The sequence is higher\n", \
              currnt_seq, expect_seq, currnt_seq + currnt_len);                           \
      LOG_SCR("TCP may not be inserted: The sequence is higher\n");                       \
      Node *new_pkt_node = create_payload_node(pkt, direction, 0);                        \
      insert_to_flow(new_pkt_node, LAST, flow, stream);                                   \
    }                                                                                     \
  } while (0)

// MALLMONDAYSALED

#define VERIFY_SEQ                                                 \
  do                                                               \
  {                                                                \
    /* Checking and updating the right sequences of packets */     \
    Node *track = flow->track_flow[is_packet_up(flow, pkt)];       \
    if (!track) /* Empty direction */                              \
      break;                                                       \
    guint8 current_direction = PP_IN_NODE(track)->is_up;           \
    guint32 current_seq = track->key;                              \
    guint32 current_len = PP_IN_NODE(track)->data_len;             \
    guint8 next_direction;                                         \
    guint32 nextpkt_seq;                                           \
    guint32 nextpkt_len;                                           \
    while (track->next != NULL) /* Has something to do */          \
    {                                                              \
      next_direction = PP_IN_NODE(track->next)->is_up;             \
      if (current_direction != next_direction)                     \
      { /* We only care the direction of the packet */             \
        track = track->next;                                       \
        continue;                                                  \
      }                                                            \
      nextpkt_seq = track->next->key;                              \
      nextpkt_len = PP_IN_NODE(track->next)->data_len;             \
      if (current_seq + current_len == nextpkt_seq)                \
      { /* The previously wrong sequence has become true */        \
        current_seq = nextpkt_seq + nextpkt_len;                   \
        current_len = nextpkt_len;                                 \
        flow->total_payload += nextpkt_len;                        \
        flow->track_flow[current_direction] = track->next;         \
        track = track->next;                                       \
        continue;                                                  \
      }                                                            \
      break; /* Meet the last packet or the one with wrong seq */  \
    }        /* The right sequence has been updated */             \
    flow->next_seq[current_direction] = current_seq + current_len; \
  } while (0)

#define FTP_PKT_HANDLE                                                                    \
  do                                                                                      \
  {                                                                                       \
    if (!flow->properties)                                                                \
    {                                                                                     \
    }                                                                                     \
    u_char const *c = PP_IN_NODE(new_pkt_node)->data;                                     \
    if (direction)                                                                        \
    { /* Recognize command from the request side */                                       \
      printf("Command: <<<%s>>>\n", c);                                                   \
      char *cmd = calloc(5, sizeof(char));                                                \
      for (int i = 0; isupper(*(c + i)) && i < 5; i++)                                    \
        cmd[i] = *(c + i);                                                                \
      if (*(cmd) == '\0')                                                                 \
        break;                                                                            \
      printf("Request command type: %s\n", cmd);                                          \
      if (strcmp(cmd, "PORT") == 0 || strcmp(cmd, "PASV") == 0)                           \
      {                                                                                   \
        guint8 temp_ip[4], temp_port[2];                                                  \
        gchar const *temp_num = (gchar *)c + 5;                                           \
        sscanf(temp_num, "%hhu,%hhu,%hhu,%hhu,%hhu,%hhu",                                 \
               &temp_ip[0], &temp_ip[1], &temp_ip[2], &temp_ip[3],                        \
               &temp_port[0], &temp_port[1]);                                             \
        guint32 new_ip_addr = temp_ip[0];                                                 \
        new_ip_addr += POW2(8) * temp_ip[1];                                              \
        new_ip_addr += POW2(16) * temp_ip[2];                                             \
        new_ip_addr += POW2(24) * temp_ip[3];                                             \
        guint32 new_port = POW2(8) * temp_port[0] + temp_port[1];                         \
        printf("New IP Address: %hhu.%hhu.%hhu.%hhu:%hu\n",                               \
               temp_ip[0], temp_ip[1], temp_ip[2], temp_ip[3], new_port);                 \
        printf("Converted IP: %u\n", new_ip_addr);                                        \
        /**(flow->related_pip) = new_port * (1ULL + G_MAXUINT32) + new_ip_addr;*/         \
      }                                                                                   \
      /* if (flow->ftp_cmd[0]) */                                                         \
      /* printf("Request command type: %s\n", flow->ftp_cmd); */                          \
    }                                                                                     \
    else if (isdigit(*c) && isdigit(*(c + 1)) && isdigit(*(c + 2)) && !isdigit(*(c + 3))) \
    { /* Recognize command from the response side */                                      \
      guint16 return_code = 999;                                                          \
      sscanf((const char *)c, "%hu", &return_code);                                       \
      printf("Response status: %hu\n", return_code);                                      \
      /* sscanf((const char *)c, "%hu", &flow->ftp_return_code); */                       \
      /* printf("Response status: %u\n", flow->ftp_return_code); */                       \
    }                                                                                     \
  } while (0)

#endif /*LOG_H*/
