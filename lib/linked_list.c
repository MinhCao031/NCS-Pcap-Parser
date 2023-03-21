#include "linked_list.h"

// Search for a node with the given key
Node *search_node(Node const *head, uint64_t key) {
  Node const *current = head;
  while (current != NULL) {
    if (current->key == key) {
      return (Node *)current;
    }
    current = current->next;
  }
  return NULL;
}

// Delete a node in list with the given key include the head node
void delete_node_with_prev(Node **prev, FILE* stream) {
  Node *tmp = (*prev)->next;
  (*prev)->next = tmp->next;
  free_node(tmp);
  LOG_DBG(stream, DBG_PARSER, "Delete success\n");
}

// Free all nodes in the list
void free_list(Node *head) {
  Node *n = head;
  while (n != NULL) {
    Node *tmp = n;
    n = n->next;
    free_node(tmp);
  }
}

// free node
void free_node(Node *node) {
  free(node->value);
  free(node);
}

// Get number of nodes in the list
uint32_t get_list_size(Node const *head) {
  uint32_t size = 0;
  // uint32_t dbg_c = 0;
  Node const *n = head;

  while (n != NULL) {
    // if (sizeof(n->value) == sizeof(parsed_payload*) && ((parsed_payload*)(n->value))->data_len == 0) {
    //   //printf("***payload 0 detected***");
    //   dbg_c++;
    //   inserted_packets -= 1;
    //   filtered_packets += 1;
    // } else 
    size++;
    n = n->next;
  }
  // printf("\n**%u##\n", dbg_c);
  return size;
}

// insert node by order desc (key) in the list
void insert_node_desc(Node **head, Node *const node, FILE* stream) {
  LOG_DBG(stream, DBG_PARSER, "Try inserting...\n");/**/
  Node *n = *head;

  if (n == NULL) {
    *head = node;
    LOG_DBG(stream, DBG_PARSER, "Head is null, attaching to node...\n");/**/
    return;
  }
  if ((int)(n->key - node->key) < 0) {
    node->next = n;
    *head = node;
    LOG_DBG(stream, DBG_PARSER, "Inserting at the first place...\n");/**/
    return;
  }
  while (n->next != NULL) {
    if ((int)(n->next->key - node->key) < 0) {
      node->next = n->next;
      n->next = node;
      LOG_DBG(stream, DBG_PARSER, "Found place to insert.\n");/**/
      return;
    }
    n = n->next;
  }
  n->next = node;
}

// insert node by order asc (key) in the list
void insert_node_asc(Node **head, Node *const node, FILE* stream) {
  LOG_DBG(stream, DBG_PARSER, "Try inserting...\n");/**/
  Node *n = *head;

  if (n == NULL) {
    *head = node;
    LOG_DBG(stream, DBG_PARSER, "Head is null, attaching to node...\n");/**/
    return;
  }
  if ((int)(n->key - node->key) > 0) {
    node->next = n;
    *head = node;
    LOG_DBG(stream, DBG_PARSER, "Inserting at the first place...\n");/**/
    return;
  }
  while (n->next != NULL) {
    if ((int)(n->next->key - node->key) > 0) {
      node->next = n->next;
      n->next = node;
      LOG_DBG(stream, DBG_PARSER, "Found place to insert.\n");/**/
      return;
    }
    n = n->next;
  }
  n->next = node;
}

// insert end of list
void insert_last_node(Node **head, Node **tail, Node *const node, FILE* stream) {
  if (!tail || !(*tail)) {
    insert_first_node(head, node);
    return;
  } else {
    LOG_DBG(stream, DBG_PARSER, "Last node actually...\n");
    Node *n = *tail;
    n->next = node;
    *tail = n->next;
  }
}

// insert at head of list
void insert_first_node(Node **head, Node *const node) {
  Node *n = *head;
  if (n == NULL) {
    *head = node;
    return;
  }
  node->next = n;
  *head = node;
}

// pop the first node in the list
void pop_first_node(Node **head) {
  if (!head) return;
  Node *n = *head;
  if (!n) return;
  Node *tmp = n;  
  *head = n->next;
  free(tmp);
}