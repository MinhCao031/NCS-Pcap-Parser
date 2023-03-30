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
#include "parsers.h"

// flow API export for external module
typedef struct __flow_base_s {
  uint16_t flags;
  uint8_t flow_state;
  uint8_t ip_proto;
  in_port_t sp; // in network by order
  in_port_t dp; // in network by order

  // version 6 or version 4
  // offset 8
  union {
    struct {
      struct in_addr sip; // in network by order
      struct in_addr dip; // in network by order
      // ipv6 address is 16 bytes each => need pad 24 bytes for same size
      uint64_t ipv4_pad[3];
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
  // proto_t *alproto;   // protocol
  void *app_data; // app specify data, update by data_handler, dont care!!!
  // offset 56
  uint32_t hash;     // full hash cache
  uint32_t flow_idx; // index of flow in flow pool, not use!!!
  // offset 64 => next cache line
  struct timeval startts;
  struct timeval lastts; // fixme last pkt timestamp of flow

  // First sequence = {First down, First up};
  uint32_t init_seq[2];

  // Next sequence = {Next down, Next up};
  uint32_t next_seq[2];

  // Total payload of the flow
  uint32_t total_payload;

  // Head of the flow
  Node *head_flow;
  // Tail of the flow
  Node *tail_flow;

  // Tracking the right sequence of packets
  Node **track_flow;

  // Total payload of the flow
  uint64_t flow_key;

} flow_base_t;

#define FLOW_PTR(f) ((flow_base_t *)(f))

#define FLOW_IS_TCP(f) (FLOW_PTR(f)->ip_proto == IPPROTO_TCP)
#define FLOW_IS_UDP(f) (FLOW_PTR(f)->ip_proto == IPPROTO_UDP)

#define FLOW_FLAGS_DEBUG 0x0010
#define FLOW_IS_DEBUG(f) (FLOW_PTR(f)->flags & FLOW_FLAGS_DEBUG)

#endif /* FLOW_API_H */
