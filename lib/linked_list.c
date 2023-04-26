#include "linked_list.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <pcap.h>

// Search for a node with the given key
Node *search_node(Node const *head, guint64 key) {
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
guint32 get_list_size(Node const *head) {
  guint32 size = 0;
  Node const *n = head;

  while (n != NULL) {
    size++;
    n = n->next;
  }
  return size;
}

// insert node by order desc (key) in the list
void insert_node_desc(Node **head, Node *const node, FILE* stream) {
  LOG_DBG(stream, *DBG_PARSER, "Try inserting...\n");/**/
  Node *n = *head;

  if (n == NULL) {
    *head = node;
    LOG_DBG(stream, *DBG_PARSER, "Head is null, attaching to node...\n");/**/
    return;
  }
  if ((int)(n->key - node->key) < 0) {
    node->next = n;
    *head = node;
    LOG_DBG(stream, *DBG_PARSER, "Inserting at the first place...\n");/**/
    return;
  }
  while (n->next != NULL) {
    if ((int)(n->next->key - node->key) < 0) {
      node->next = n->next;
      n->next = node;
      LOG_DBG(stream, *DBG_PARSER, "Found place to insert.\n");/**/
      return;
    }
    n = n->next;
  }
  n->next = node;
}

void insert_payload_asc(Node **head, Node **tail, Node *const node, FILE* stream) {
  guint8 node_direction = PP_IN_NODE(node)->is_up;
  LOG_DBG(stream, *DBG_PARSER, "~~~TRY INSERTING...\n");/**/
  Node *n = *head;

  if (n == NULL) {
    *head = node;
    LOG_DBG(stream, *DBG_PARSER, "~~~HEAD IS NULL\n");/**/
    return;
  }
  while (n->next != NULL) {
    guint8 n_direction = PP_IN_NODE(n->next)->is_up;
    if ((int)(n->next->key - node->key) > 0 && n_direction == node_direction) {
      node->next = n->next;
      n->next = node;
      *head = node;
      LOG_DBG(stream, *DBG_PARSER, "~~~FOUND PLACE TO INSERT\n");/**/
      return;
    }
    n = n->next;
  }
  n->next = node;
  *head = node;
  *tail = node;
}


// insert node by order asc (key) in the list
void insert_node_asc(Node **head, Node *const node, FILE* stream) {
  Node *n = *head;

  if (n == NULL) {
    *head = node;
    LOG_DBG(stream, *DBG_PARSER, "Head is null, attaching to node...\n");/**/
    return;
  }
  if ((int)(n->key - node->key) > 0) {
    node->next = n;
    *head = node;
    LOG_DBG(stream, *DBG_PARSER, "Inserting at the first place...\n");/**/
    return;
  }
  while (n->next != NULL) {
    if ((int)(n->next->key - node->key) > 0) {
      node->next = n->next;
      n->next = node;
      LOG_DBG(stream, *DBG_PARSER, "Found place to insert.\n");/**/
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