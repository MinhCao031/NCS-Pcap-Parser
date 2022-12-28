#ifndef LINKED_LIST_H
#define LINKED_LIST_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct Node {
  uint64_t key;
  void *value;
  struct Node *next;
} Node;

// insert node by order desc (key) in the list
void insert_node_desc(Node **head, Node *const new_node, FILE* fptr);
// insert node by order asc (key) in the list
void insert_node_asc(Node **head, Node *const node);
// insert end of list
void insert_last_node(Node **head, Node *const node);
// insert head of list
void insert_first_node(Node **head, Node *const node);
// insert to waiting list
void insert_to_wait(Node **head, Node node, FILE* fptr);

// Search for a node with the given key
Node *search_node(Node const *head, uint64_t key);
// Delete a node with the given key
void delete_node(Node **head, uint64_t key, FILE* fptr);
// Free all nodes in the list
void free_list(Node *head);
// free a node and it's data
void free_node(Node *node);
// Get number of nodes in the list
uint get_list_size(Node const *head);
// pop the head node in the list
Node *pop_first_node(Node **head);

#endif
