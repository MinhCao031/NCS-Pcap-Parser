#include "hash_table.h"


// hash function
uint32_t hash(uint64_t x, uint64_t len) {
  x = ((x >> 16) ^ x) * 0x45d9f3b;
  x = ((x >> 16) ^ x) * 0x45d9f3b;
  x = ((x >> 16) ^ x);
  // x = x % (len*len - 3*len  + 5);
  return x % len;
}

// create a new hash table with all entries 0
HashTable create_hash_table(uint64_t size) {
  HashTable table = {size, calloc(size, sizeof(Node *))};
  assert(table.lists != NULL);
  return table;
}

// insert a new flow into the hash table
void insert_new_flow(HashTable table, Node *const flow_node) {
  uint32_t index = hash(flow_node->key, table.size);
  insert_first_node(&table.lists[index], flow_node);
}

// insert a packet data to a flow
void insert_to_flow(Node *const pkt_node, enum InsertAlgorihm insert_type,
                    Node **flow_head, Node **flow_tail, FILE* stream) {
  if (insert_type == DESC) {
    insert_node_desc(flow_head, pkt_node, stream);
  }

  if (insert_type == ASC) {
    insert_node_asc(flow_head, pkt_node, stream);
  }

  if (insert_type == FIRST) {
    insert_first_node(flow_head, pkt_node);
  }

  if (insert_type == LAST) {
    insert_last_node(flow_head, flow_tail, pkt_node, stream);
  }
}

// search flow by key in the hash table
flow_base_t *search_flow(HashTable const table, uint64_t key, FILE* stream) {
  uint32_t index = hash(key, table.size);
  Node *head_flow = table.lists[index];

  if (!head_flow) {
    return NULL;
  } else {
    LOG_DBG(stream, DBG_PARSER, "Finding node with index = %d...\n", index);
    Node *n = search_node(head_flow, key);
    LOG_DBG(stream, DBG_PARSER, "Done searching node with index = %d...\n", index);
    return !n ? NULL : (flow_base_t *)n->value;
  }
}

// remove flow from hash table
void delete_flow(HashTable table, uint64_t key) {
  printf("WARNING: You're trying to use function delete_flow, which doesn't work and will be abandoned\n");
//   uint32_t index = hash(key, table.size);
//   Node *n = table.lists[index];
//   delete_node(&n, key, NULL);

//   if (n == NULL) {
//     return;
//   }

//   // find the flow node by key then free all package nodes in the flow, then
//   // delete flow node
//   if (n->key == key) {
//     free_flow_direction(((flow_base_t *)n->value)->flow_down);
//     free_flow_direction(((flow_base_t *)n->value)->flow_up);
//     table.lists[index] = n->next;
//     free_node(n);
//   } else {
//     while (n->next != NULL) {
//       if (n->next->key == key) {
//         free_flow_direction(((flow_base_t *)n->next->value)->flow_down);
//         free_flow_direction(((flow_base_t *)n->next->value)->flow_up);
//         Node *tmp = n->next;
//         n->next = n->next->next;
//         free_node(tmp);
//         return;
//       }
//       n = n->next;
//     }
//   }
//   printf("flow with key %ld not found to delete\n", key);
}

// free hash table
void free_hash_table(HashTable table) {
  for (uint32_t i = 0; i < table.size; i++) {
    Node* flow_temp = table.lists[i];
    if (flow_temp != NULL) {
      // free each package nodes in each flow
      while (flow_temp != NULL) {
        Node *tmp = flow_temp;
        free_flow_direction(((flow_base_t *)tmp->value)->flow_down);
        free_flow_direction(((flow_base_t *)tmp->value)->flow_up);

        flow_temp = flow_temp->next;
      }
    }
    // free all flow nodes
    free_list(table.lists[i]);
  }
  free(table.lists);
}



// Get number of packets in hash table
uint32_t count_packets(HashTable const table) {

  int count = 0;
  Node const *node_flow_temp;

  for (size_t i = 0; i < table.size; i++) {
    node_flow_temp = table.lists[i];
    while (node_flow_temp != NULL) {
      flow_base_t* flow_temp = ((flow_base_t *)node_flow_temp->value);
      Node *flow_down_temp = flow_temp->flow_down;
      count += get_list_size(flow_down_temp);
      Node *flow_up_temp = flow_temp->flow_up;
      count += get_list_size(flow_up_temp);
      node_flow_temp = node_flow_temp->next;
    }
  }
  return count;
}

// get number of flows in hashtable
uint32_t count_flows(HashTable const table) {

  int count = 0;
  Node *temp;

  for (size_t i = 0; i < table.size; i++) {
    temp = table.lists[i];
    uint32_t list_size = get_list_size(temp);
    count += list_size;
  }
  return count;
}

// get number of nodes in a flow
uint32_t get_flow_size(flow_base_t const *flow) {
  uint32_t list_down_size = get_list_size(flow->flow_down);
  uint32_t list_up_size = get_list_size(flow->flow_up);
  return list_down_size + list_up_size;
}

// free a node value and it's data in a flow
void free_payload_node(Node *payload_node) {
  // free payload data
  free((u_char *)((parsed_payload *)payload_node->value)->data);
  //// ((parsed_payload *)payload_node->value)->data = NULL;

  free_node(payload_node);
}

// free all nodes in a flow
void free_flow_direction(Node *flow_direction) {
  if (!flow_direction) return;

  Node *temp = flow_direction;
  while (temp != NULL) {
    Node *next = temp->next;
    free_payload_node(temp);
    temp = next;
  }
}
