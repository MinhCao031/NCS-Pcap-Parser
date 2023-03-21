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

/* These below are just for debug */
#define DBG_ALL 1
// 1 to print error, otherwise 0
#define DBG_ERROR (DBG_ALL & 1)
// 1 to print parser's process, otherwise 0
#define DBG_PARSER (DBG_ALL & 1)
// 1 to check and filter wrong sequences out, otherwise 0
#define DBG_PKT_SEQ (DBG_ALL & 1)
// 1 to print flow's info, otherwise 0
#define DBG_FLOW (DBG_ALL & 1)
// 1 to print data in the hex form, otherwise 0
#define DBG_PAYLOAD (DBG_ALL & DBG_FLOW & 0)
// 1 to print to console, otherwise 0
#define DBG_CONSOLE (DBG_ALL & 1)

// ASC to insert packet in ascending sequence, otherwise DESC
#define DATA_DIRECTION ASC
#define PCAP_FILE "sample_SMTP_2.pcap"
#define SEC2NANO 1000000000
#define LIMIT_PACKET 2700000
#define HASH_TABLE_SIZE 30030

// If a sequence is too far from the previous one, that packet is consider ignored
#define MAX_BYTE_DISTANCE (uint64_t)536870912

// Some txt file to print when debugging
#define FILELOG_ERR "outputERROR.txt"
#define FILELOG_1 "output_parse_packet.txt"
#define FILELOG_2 "output_seq_filter.txt"
#define FILELOG_3 "output_wireshark.txt"
#define FILELOG_4 "output_others.txt"

#define OUTPUT_0 stdout
#define OUTPUT_1 fopen(FILELOG_1, "a+")
#define OUTPUT_2 fopen(FILELOG_2, "a+")
#define OUTPUT_3 fopen(FILELOG_3, "a+")
#define OUTPUT_4 fopen(FILELOG_4, "a+")

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

// Print debug for flow_up
#define LOG_INSERT_FLOW_UP                                                                \
    do                                                                                    \
    {                                                                                     \
        LOG_DBG(stream, DBG_PARSER, "UP...\n");                                           \
        LOG_DBG(stream, DBG_PARSER, "Checking flow status = %u\n", flow->pkt_close_flow); \
    } while (0)

// Print debug for flow_down
#define LOG_INSERT_FLOW_DOWN                                                              \
    do                                                                                    \
    {                                                                                     \
        LOG_DBG(stream, DBG_PARSER, "DOWN...\n");                                         \
        LOG_DBG(stream, DBG_PARSER, "Checking flow status = %u\n", flow->pkt_close_flow); \
    } while (0)

// Try inserting to flow_up
#define TRY_INSERT_FLOW_UP                                                                                    \
    do                                                                                                        \
    {                                                                                                         \
        uint32_t sequence = pkt.tcp.seq;                                                                      \
        LOG_DBG(stream, DBG_PARSER, "Check again sequence: %u > %u\n", sequence, flow->init_seq_up);          \
        if ((uint32_t)(sequence - flow->init_seq_up) > MAX_BYTE_DISTANCE)                                     \
        {                                                                                                     \
            LOG_DBG(stream, DBG_PARSER, "Lost sequence: %u < %u\n", sequence, flow->init_seq_up);             \
            break;                                                                                            \
        }                                                                                                     \
        else if (flow->pkt_close_flow / 10 > 0)                                                               \
        {                                                                                                     \
            LOG_DBG(stream, DBG_PARSER, "Too late, flow closed\n");                                           \
            break;                                                                                            \
        }                                                                                                     \
        else                                                                                                  \
        {                                                                                                     \
            uint32_t last_data_length = ((parsed_payload *)((flow->last_up)->value))->data_len;               \
            uint32_t last_seq = (flow->last_up)->key;                                                         \
            Node *new_pkt_node = create_payload_node(pkt);                                                    \
            uint32_t data_length = ((parsed_payload *)new_pkt_node->value)->data_len;                         \
            LOG_INSERT_FLOW_UP;                                                                               \
            flow->total_payload_up += data_length;                                                            \
            if (last_seq < sequence || (last_seq == sequence && data_length >= last_data_length))             \
            {                                                                                                 \
                LOG_DBG(stream, DBG_PARSER, "Inserting as newest TCP\n");                                     \
                insert_to_flow(new_pkt_node, 3 - DATA_DIRECTION, &(flow->flow_up), &(flow->last_up), stream); \
            }                                                                                                 \
            else                                                                                              \
            {                                                                                                 \
                LOG_DBG(stream, DBG_PARSER, "Inserting as not-so-new TCP: %u\n", sequence);                   \
                insert_to_flow(new_pkt_node, DATA_DIRECTION, &(flow->flow_up), NULL, stream);                 \
            }                                                                                                 \
            inserted_packets += 0;                                                                            \
            LOG_DBG(stream, DBG_PARSER, "Done inserting TCP\n");                                              \
        }                                                                                                     \
    } while (0)

// Try inserting to flow_down
#define TRY_INSERT_FLOW_DOWN                                                                                      \
    do                                                                                                            \
    {                                                                                                             \
        uint32_t sequence = pkt.tcp.seq;                                                                          \
        LOG_DBG(stream, DBG_PARSER, "Check again sequence: %u > %u\n", sequence, flow->init_seq_down);            \
        if ((uint32_t)(sequence - flow->init_seq_down) > MAX_BYTE_DISTANCE)                                       \
        {                                                                                                         \
            LOG_DBG(stream, DBG_PARSER, "Lost sequence: %u < %u\n", sequence, flow->init_seq_down);               \
            break;                                                                                                \
        }                                                                                                         \
        else if (flow->pkt_close_flow % 10 > 0)                                                                   \
        {                                                                                                         \
            LOG_DBG(stream, DBG_PARSER, "Too late, flow closed\n");                                               \
            break;                                                                                                \
        }                                                                                                         \
        else                                                                                                      \
        {                                                                                                         \
            uint32_t last_data_length = ((parsed_payload *)((flow->last_down)->value))->data_len;                 \
            uint32_t last_seq = (flow->last_down)->key;                                                           \
            Node *new_pkt_node = create_payload_node(pkt);                                                        \
            uint32_t data_length = ((parsed_payload *)new_pkt_node->value)->data_len;                             \
            LOG_INSERT_FLOW_DOWN;                                                                                 \
            flow->total_payload_down += data_length;                                                              \
            if (last_seq < sequence || (last_seq == sequence && data_length >= last_data_length))                 \
            {                                                                                                     \
                LOG_DBG(stream, DBG_PARSER, "Inserting as newest TCP\n");                                         \
                insert_to_flow(new_pkt_node, 3 - DATA_DIRECTION, &(flow->flow_down), &(flow->last_down), stream); \
            }                                                                                                     \
            else                                                                                                  \
            {                                                                                                     \
                LOG_DBG(stream, DBG_PARSER, "Inserting as not-so-new TCP: %u\n", sequence);                       \
                insert_to_flow(new_pkt_node, DATA_DIRECTION, &(flow->flow_down), NULL, stream);                   \
            }                                                                                                     \
            inserted_packets += 0;                                                                                \
            LOG_DBG(stream, DBG_PARSER, "Done inserting TCP\n");                                                  \
        }                                                                                                         \
    } while (0)

#define TRY_INSERT_FLOW                                                                                       \
do                                                                                                            \
{                                                                                                             \
    if (flow->is_last_pkt_up == is_packet_up(flow, pkt))                                                      \
    {                                                                                                         \
        if (pkt.tcp.seq == flow->nxt_pkt_seq && pkt.tcp.ack_seq == flow->current_ack)                         \
        {                                                                                                     \
            LOG_DBG(stream, DBG_PARSER,                                                                       \
                "TCP inserted with the same flow with the last packet\n"                                      \
                "Comparing get True: SEQ(%u & %u), ACK(%u & %u)\n",                                           \
                flow->nxt_pkt_seq, pkt.tcp.seq, flow->current_ack, pkt.tcp.ack_seq                            \
            );                                                                                                \
            Node *new_pkt_node = create_payload_node(pkt);                                                    \
            flow->current_seq = pkt.tcp.seq;                                                                  \
            flow->nxt_pkt_seq = pkt.tcp.seq + pkt.payload.data_len;                                           \
            insert_to_flow(new_pkt_node, 3 - DATA_DIRECTION, &(flow->head_flow), &(flow->tail_flow), stream); \
            inserted_packets += 1;                                                                            \
            flow->total_payload += pkt.payload.data_len;                                                      \
        }                                                                                                     \
        else                                                                                                  \
        {                                                                                                     \
            LOG_DBG(stream, DBG_PARSER,                                                                       \
                "TCP not inserted with the same flow with the last packet\n"                                  \
                "Comparing get False: SEQ(%u & %u), ACK(%u & %u)\n",                                          \
                flow->nxt_pkt_seq, pkt.tcp.seq, flow->current_ack, pkt.tcp.ack_seq                            \
            );                                                                                                \
        }                                                                                                     \
    }                                                                                                         \
    else                                                                                                      \
    {                                                                                                         \
        if (pkt.tcp.seq == flow->current_ack && pkt.tcp.ack_seq == flow->nxt_pkt_seq)                         \
        {                                                                                                     \
            LOG_DBG(stream, DBG_PARSER, "TCP inserted with the opposite flow with the last packet\n"          \
                                        "Comparing get True: SEQ(%u & %u), ACK(%u & %u)\n",                   \
                    flow->current_ack, pkt.tcp.seq, flow->nxt_pkt_seq, pkt.tcp.ack_seq);                      \
            Node *new_pkt_node = create_payload_node(pkt);                                                    \
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
            LOG_DBG(stream, DBG_PARSER, "TCP not inserted with the opposite flow with the last packet\n"      \
                                        "Comparing get False: SEQ(%u & %u), ACK(%u & %u)\n",                  \
                    flow->current_ack, pkt.tcp.seq, flow->nxt_pkt_seq, pkt.tcp.ack_seq);                      \
        }                                                                                                     \
    }                                                                                                         \
    LOG_DBG(stream, DBG_PARSER, "Tracking seq = %u -> %u, ack = %u\n",                                        \
            flow->current_seq, flow->nxt_pkt_seq, flow->current_ack                                           \
    );                                                                                                        \
} while (0)

#define INSERT_FINAL_NODE(close_type)                                                 \
    do                                                                                \
    {                                                                                 \
        /* close_type is for flow_base_t.pkt_close_flow */                            \
        if (get_flow_direction(flow, pkt, stream) == &(flow->flow_up))                \
        {                                                                             \
            LOG_DBG(stream, DBG_PARSER, "FINAL: UP...\n");                            \
            TRY_INSERT_FLOW_UP;                                                       \
            flow->pkt_close_flow += 10;                                               \
            break;                                                                    \
        }                                                                             \
        else if (get_flow_direction(flow, pkt, stream) == &(flow->flow_down))         \
        {                                                                             \
            LOG_DBG(stream, DBG_PARSER, "FINAL: DOWN...\t");                          \
            TRY_INSERT_FLOW_DOWN;                                                     \
            flow->pkt_close_flow += 1;                                                \
            break;                                                                    \
        }                                                                             \
        else                                                                          \
            LOG_DBG(stream, DBG_PARSER, "UNEXPECTED%s(ACK)!!!",                       \
                    (close_type == 1 ? " FIN/" : (close_type == 0 ? " RST/" : " "))); \
    } while (0)
#endif /*LOG_H*/

    /*
    // Try inserting to flow_down
    #define TRY_INSERT_FLOW_DOWN(leng_data)                                       \
        Node *new_pkt_node = create_payload_node(pkt);                    \
        uint32_t data_length = ((parsed_payload *)new_pkt_node->value)->data_len; \
        if (leng_data == 0)                                                       \
            flow->exp_seq_down += 1;                                              \
        else                                                                      \
        {                                                                         \
            flow->exp_seq_down += data_length;                                    \
        }                                                                         \
        insert_to_flow(new_pkt_node, DATA_DIRECTION, &(flow->flow_down), stream); \
        LOG_DBG(stream, DBG_PARSER, "Done inserting TCP\n");                      \
        inserted_packets += 0;
    */