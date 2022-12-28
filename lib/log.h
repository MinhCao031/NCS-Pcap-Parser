#ifndef LOG_H
#define LOG_H

#include <stdlib.h>
#pragma once

#define LIMIT_PACKET 2700000
#define HASH_TABLE_SIZE 50
#define PCAP_FILE "TCPsample.pcap"

/* These below are just for debug */
#define FILELOG_ERR "outputERROR.txt"
#define FILELOG_1 "output1.txt"
#define FILELOG_2 "output2.txt"

#define OUTPUT_E fopen(FILELOG_ERR, "a+")
#define OUTPUT_0 stdout
#define OUTPUT_1 fopen(FILELOG_1, "a+")
#define OUTPUT_2 fopen(FILELOG_2, "a+")

// 1 for fprintf, 0 for doing nothing
#define DBG_ERROR 1
#define DBG_PARSER 1
#define DBG_FLOW 1
#define DBG_PAYLOAD 1

// 0 to check sequence, 1 for auto true
#define DBG_PKT_SEQ 0

// Format for printing debug info
#define LOG_DBG(stream, print, format, others...) \
    {                                             \
        if (print)                                \
        {                                         \
            fprintf(stream, format, ##others);    \
            fflush(stream);                       \
            /*fclose(stream);*/                   \
        }                                         \
    }

#endif /*LOG_H*/