#ifndef LINKED_LIST_H
#define LINKED_LIST_H

#include "parsers.h"
#include <stdio.h>

typedef struct Node {
  guint64 key; // Absolute sequence
  void *value;
  struct Node *next;
} Node;

// insert node by order desc (key) in the list
void insert_node_desc(Node **head, Node *const new_node, FILE* stream);
// insert node by order asc (key) in the list
void insert_node_asc(Node **head, Node *const node, FILE* stream);
// insert node by order asc (key) in the list
void insert_payload_asc(Node **head, Node **tail, Node *const node, FILE* stream);
// insert end of list
void insert_last_node(Node **head, Node **tail, Node *const node, FILE* stream);
// insert head of list
void insert_first_node(Node **head, Node *const node);
// Search for a node with the given key
Node *search_node(Node const *head, guint64 key);
// Delete a node with the given key
void delete_node_with_prev(Node** prev, FILE* stream);
// Free all nodes in the list
void free_list(Node *head);
// free a node and it's data
void free_node(Node *node);
// Get number of nodes in the list
guint32 get_list_size(Node const *head);
// pop the head node in the list
void pop_first_node(Node **head);

#endif
  