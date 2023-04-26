/* Copyright (C) Cerberus - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by Dao Van Huy <huy.dao@cerberus.com.vn>
 */
/*
 * File:   flow_api.h
 * Author: Dao Van Huy <huy.dao@cerberus.com.vn>
 *
 * Created on Tue Nov 08 2022
 */
#ifndef FLOW_API_H
#define FLOW_API_H

#pragma once

#include "linked_list.h"

#include <stdio.h>
#include <netinet/in.h>

// flow API export for external module
typedef struct __flow_base_s {
  guint16   flags;
  guint8    flow_state;
  guint8    ip_proto;
  in_port_t sp;             // in network by order (2 bytes)
  in_port_t dp;             // in network by order (2 bytes)

  // version 6 or version 4
  // offset 8
  union {
    struct {
      struct  in_addr sip;  // in network by order (4 bytes)
      struct  in_addr dip;  // in network by order (4 bytes)
      guint64 spip;         // combination of port & IP identity (from source side)
      guint64 dpip;         // combination of port & IP identity (from destination side)
      guint64 ipv4_pad;     // ipv6 address is 16 bytes each => need pad 8 bytes for same size
    };

    struct {
      struct in6_addr ip6_src; /* source address */
      // NOTE: with IPv6, when Routing Header is present => dst addr in IPv6
      // header maybe is router node, not the real client or server, so
      // metadata_decoder function will decode Routing Header and set the real
      // address which called final destination address
      struct in6_addr ip6_dst; /* final destination address */
    };
  };
  // offset 40
  // proto_t *alproto;      // protocol
  void     *app_data;       // app specify data, update by data_handler, dont care!!!
  // offset 56
  guint32   hash;           // full hash cache
  guint32   flow_idx;       // index of flow in flow pool, not use!!!
  // offset 64 => next cache line
  struct timeval startts;
  struct timeval lastts;    // fixme last pkt timestamp of flow
  // offset 96
  guint32   init_seq[2];    // First sequence = {First down, First up};
  guint32   next_seq[2];    // Next sequence = {Next down, Next up};
  guint32   total_payload;  // Total payload of the flow
  // offset 116
  Node     *head_flow;      // Head of the flow
  Node     *tail_flow;      // Tail of the flow
  Node    **track_flow;     // Tracking the right sequence of packets
  guint64   flow_key;       // Flow identity
  // offset 148
  void     *properties;     // Some properties of the flow, depend on protocol
} flow_base_t;


#define FLOW_PTR(f) ((flow_base_t *)(f))
#define FLOW_IN_NODE(node) FLOW_PTR((node)->value)

#define FLOW_IS_TCP(f) (FLOW_PTR(f)->ip_proto == IPPROTO_TCP)
#define FLOW_IS_UDP(f) (FLOW_PTR(f)->ip_proto == IPPROTO_UDP)

#define FLOW_FLAGS_DEBUG 0x0010
#define FLOW_IS_DEBUG(f) (FLOW_PTR(f)->flags & FLOW_FLAGS_DEBUG)

#endif /* FLOW_API_H */
