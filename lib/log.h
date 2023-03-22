#ifndef LOG_H
#define LOG_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
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

#define PCAP_FILE "sample_FTP_1.pcap"

/* These below are just for debug */
#define DBG_ALL 1
// 1 to calculate time, otherwise 0
#define DBG_TIMER (DBG_ALL & 0)
// 1 to print parser's process, otherwise 0
#define DBG_PARSER (DBG_ALL & 1)
// 1 to check and filter wrong sequences out, otherwise 0
#define DBG_PKT_SEQ (DBG_ALL & 0)
// 1 to print flow's info, otherwise 0
#define DBG_FLOW (DBG_ALL & 1)
// 1 to print data in the hex form, otherwise 0
#define DBG_PAYLOAD (DBG_ALL & DBG_FLOW & 0)
// 1 to print to console, otherwise 0
#define DBG_CONSOLE (DBG_ALL & 1)

// ASC to insert packet in ascending sequence, otherwise DESC
#define DATA_DIRECTION ASC
#define SEC2NANO 1000000000
#define LIMIT_PACKET 2700000
#define HASH_TABLE_SIZE 30030

// If a sequence is too far from the previous one, that packet is consider ignored
#define MAX_BYTE_DISTANCE (uint64_t)536870912

// Some txt file to print when debugging
#define FILELOG_1 "output_parse_packet.txt"
#define FILELOG_2 "output_seq_filter.txt"
#define FILELOG_3 "output_wireshark.txt"

#if DBG_PARSER == 1
#define OUTPUT_1 fopen(FILELOG_1, "a+")
#else
#define OUTPUT_1 NULL
#endif

#if DBG_PKT_SEQ == 1
#define OUTPUT_2 fopen(FILELOG_2, "a+")
#else
#define OUTPUT_2 NULL
#endif

#if DBG_FLOW == 1
#define OUTPUT_3 fopen(FILELOG_3, "a+")
#else
#define OUTPUT_3 NULL
#endif

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
    do                                            \
    {                                             \
        if (!stream || !(print))                  \
            break;                                \
        fprintf(stream, format, ##others);        \
        fflush(stream);                           \
    } while (0)

#define LOG_SCR(format, others...) \
    do                             \
    {                              \
        if (!DBG_CONSOLE)          \
            break;                 \
        printf(format, ##others);  \
    } while (0)

// Get full timestamp
#define GET_FULL_TIMESTAMP                                  \
    char full_timestamp[80];                                \
    struct tm ts = *localtime(&((header_pcap->ts).tv_sec)); \
    strftime(full_timestamp, sizeof(full_timestamp), "%a %Y-%m-%d %H:%M:%S %Z", &ts);

#define PROCESS_PACKET_TIME(time_limit_warning)                        \
    if (DBG_TIMER)                                                     \
    {                                                                  \
        process_time = (pkt_end.tv_sec - pkt_start.tv_sec) * SEC2NANO; \
        process_time += pkt_end.tv_nsec - pkt_start.tv_nsec;           \
        process_time_total += process_time;                            \
        if (process_time < 1001)                                       \
            sttstc[process_time / 100 - 3] += 1;                       \
        else if (process_time < 10001)                                 \
            sttstc[6 + (process_time + 999) / 1000] += 1;              \
        else if (process_time < 100001)                                \
            sttstc[15 + (process_time + 9999) / 10000] += 1;           \
        else                                                           \
            sttstc[26] += 1;                                           \
        LOG_DBG(fout_parser, (process_time > time_limit_warning),      \
                "Packet%8u:%7lu nanosec stoped at step %d of 6\n",     \
                packet_count, process_time, progress_pkt);             \
    }

#define STATISTIC_PACKET_TIME                                                                            \
    if (DBG_TIMER)                                                                                       \
    {                                                                                                    \
        LOG_DBG(fout_parser, 1, "Packet time total: %lu\n", process_time_total);                         \
        LOG_DBG(fout_parser, 1, "Average time process: %lf\n", 1.0 * process_time_total / packet_count); \
        for (uint8_t i = 0; i < 8; i++)                                                                  \
            LOG_DBG(fout_parser, 1, " =%-6u nanosec: %5u time(s)\n", (i + 3) * 100, sttstc[i]);          \
        for (uint8_t i = 8; i < 17; i++)                                                                 \
            LOG_DBG(fout_parser, 1, "<=%-6u nanosec: %5u time(s)\n", (i - 6) * 1000, sttstc[i]);         \
        for (uint8_t i = 17; i < 26; i++)                                                                \
            LOG_DBG(fout_parser, 1, "<=%-6u nanosec: %5u time(s)\n", (i - 15) * 10000, sttstc[i]);       \
        LOG_DBG(fout_parser, 1, "> 100000 nanosec: %5u time(s)\n", sttstc[26]);                          \
    }

// Try to insert to flow
#define TRY_INSERT_FLOW                                                                                           \
    do                                                                                                            \
    {                                                                                                             \
        if (flow->is_last_pkt_up == is_packet_up(flow, pkt))                                                      \
        {                                                                                                         \
            if (pkt.tcp.seq == flow->nxt_pkt_seq && pkt.tcp.ack_seq == flow->current_ack)                         \
            {                                                                                                     \
                LOG_DBG(stream, DBG_PARSER,                                                                       \
                        "TCP inserted with the same flow with the last packet\n"                                  \
                        "Comparing get True: SEQ(%u & %u), ACK(%u & %u)\n",                                       \
                        flow->nxt_pkt_seq, pkt.tcp.seq, flow->current_ack, pkt.tcp.ack_seq);                      \
                Node *new_pkt_node = create_payload_node(pkt, is_packet_up(flow, pkt));                           \
                flow->current_seq = pkt.tcp.seq;                                                                  \
                flow->nxt_pkt_seq = pkt.tcp.seq + pkt.payload.data_len;                                           \
                insert_to_flow(new_pkt_node, 3 - DATA_DIRECTION, &(flow->head_flow), &(flow->tail_flow), stream); \
                inserted_packets += 1;                                                                            \
                flow->total_payload += pkt.payload.data_len;                                                      \
            }                                                                                                     \
            else                                                                                                  \
            {                                                                                                     \
                LOG_DBG(stream, DBG_PARSER,                                                                       \
                        "TCP not inserted with the same flow with the last packet\n"                              \
                        "Comparing get False: SEQ(%u & %u), ACK(%u & %u)\n",                                      \
                        flow->nxt_pkt_seq, pkt.tcp.seq, flow->current_ack, pkt.tcp.ack_seq);                      \
            }                                                                                                     \
        }                                                                                                         \
        else                                                                                                      \
        {                                                                                                         \
            if (pkt.tcp.seq == flow->current_ack && pkt.tcp.ack_seq == flow->nxt_pkt_seq)                         \
            {                                                                                                     \
                LOG_DBG(stream, DBG_PARSER,                                                                       \
                        "TCP inserted with the opposite flow with the last packet\n"                              \
                        "Comparing get True: SEQ(%u & %u), ACK(%u & %u)\n",                                       \
                        flow->current_ack, pkt.tcp.seq, flow->nxt_pkt_seq, pkt.tcp.ack_seq);                      \
                Node *new_pkt_node = create_payload_node(pkt, is_packet_up(flow, pkt));                           \
                flow->current_ack = flow->nxt_pkt_seq;                                                            \
                flow->current_seq = pkt.tcp.seq;                                                                  \
                flow->nxt_pkt_seq = pkt.tcp.seq + pkt.payload.data_len;                                           \
                flow->is_last_pkt_up = 1 - flow->is_last_pkt_up;                                                  \
                insert_to_flow(new_pkt_node, 3 - DATA_DIRECTION, &(flow->head_flow), &(flow->tail_flow), stream); \
                inserted_packets += 1;                                                                            \
                flow->total_payload += pkt.payload.data_len;                                                      \
            }                                                                                                     \
            else                                                                                                  \
            {                                                                                                     \
                LOG_DBG(stream, DBG_PARSER,                                                                       \
                        "TCP not inserted with the opposite flow with the last packet\n"                          \
                        "Comparing get False: SEQ(%u & %u), ACK(%u & %u)\n",                                      \
                        flow->current_ack, pkt.tcp.seq, flow->nxt_pkt_seq, pkt.tcp.ack_seq);                      \
            }                                                                                                     \
        }                                                                                                         \
        LOG_DBG(stream, DBG_PARSER, "Tracking seq = %u -> %u, ack = %u\n",                                        \
                flow->current_seq, flow->nxt_pkt_seq, flow->current_ack);                                         \
    } while (0)

#endif /*LOG_H*/

/*
Tracking #1   SEQ = 3738363856 => 3738363890, ACK =          0
Tracking #2   SEQ = 3738363856 => 3738363956, ACK =          0
Tracking #6   SEQ = 2934727088 => 2934727269, ACK = 2126795697
Tracking #7   SEQ = 2126795697 => 2126795706, ACK = 2934727269
Tracking #9   SEQ = 2934727269 => 2934727406, ACK = 2126795706
Tracking #10  SEQ = 2126795706 => 2126795718, ACK = 2934727406
Tracking #11  SEQ = 2934727406 => 2934727424, ACK = 2126795718
Tracking #12  SEQ = 2126795718 => 2126795748, ACK = 2934727424
Tracking #13  SEQ = 2934727424 => 2934727442, ACK = 2126795748
Tracking #14  SEQ = 2126795748 => 2126795766, ACK = 2934727442
Tracking #15  SEQ = 2934727442 => 2934727472, ACK = 2126795766
Tracking #16  SEQ = 2126795766 => 2126795802, ACK = 2934727472
Tracking #17  SEQ = 2934727472 => 2934727480, ACK = 2126795802
Tracking #18  SEQ = 2126795802 => 2126795841, ACK = 2934727480
Tracking #19  SEQ = 2934727480 => 2934727494, ACK = 2126795841
Tracking #20  SEQ = 2126795841 => 2126795847, ACK = 2934727494
Tracking #21  SEQ = 2934727494 => 2934727550, ACK = 2126795847
Tracking #22  SEQ = 2126795847 => 2126797307, ACK = 2934727550 *!*
Tracking #23  SEQ = 2126797307 => 2126798767, ACK = 2934727550 *!*
Tracking #24  SEQ = 2126798767 => 2126800227, ACK = 2934727550 *!*
Tracking #25  SEQ = 2126800227 => 2126801687, ACK = 2934727550 *!*
Tracking #27  SEQ = 2126795847 => 2126797299, ACK = 2934727550
Tracking #32  SEQ = 2126797299 => 2126798751, ACK = 2934727550
Tracking #33  SEQ = 2126798751 => 2126800203, ACK = 2934727550
Tracking #35  SEQ = 2126800203 => 2126801655, ACK = 2934727550
Tracking #36  SEQ = 2126801655 => 2126803107, ACK = 2934727550
Tracking #38  SEQ = 2126803107 => 2126804559, ACK = 2934727550
Tracking #39  SEQ = 2126804559 => 2126806011, ACK = 2934727550
Tracking #41  SEQ = 2126806011 => 2126807463, ACK = 2934727550
Tracking #42  SEQ = 2126807463 => 2126808915, ACK = 2934727550
Tracking #44  SEQ = 2126808915 => 2126810367, ACK = 2934727550
Tracking #45  SEQ = 2126810367 => 2126810396, ACK = 2934727550
Tracking #52  SEQ = 2934727550 => 2934727578, ACK = 2126810396
Tracking #54  SEQ = 2126810396 => 2126810402, ACK = 2934727578
Tracking #56  SEQ = 2934727578 => 2934727626, ACK = 2126810402
Tracking #60  SEQ = 3738363856 => 3738364057, ACK =          0



*/