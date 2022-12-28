
#include <pcap.h>
#include <assert.h>
#include "linked_list.h"
#include "log.h"

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
void delete_node(Node **head, uint64_t key, FILE* stream) {
  Node *n = *head;
  if (n == NULL) {
    return;
  }
  if (n->key == key) {
    Node *tmp = n;
    *head = n->next;
    free_node(tmp);
    return;
  }
  while (n->next != NULL) {
    if (n->next->key == key) {
      Node *tmp = n->next;
      n->next = tmp->next;
      free_node(tmp);
      LOG_DBG(stream, DBG_PARSER, "Delete success\n");
      return;
    }
    n = n->next;
  }
  LOG_DBG(stream, DBG_PARSER, "Node with key %lu not found\n", key);
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
uint get_list_size(Node const *head) {
  uint size = 0;
  Node const *n = head;
  while (n != NULL) {
    n = n->next;
    size++;
  }
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
void insert_node_asc(Node **head, Node *const node) {
  Node *n = *head;
  if (n == NULL) {
    *head = node;
    return;
  }
  if ((int)(n->key - node->key) > 0) {
    node->next = n;
    *head = node;
    return;
  }
  while (n->next != NULL) {
    if ((int)(n->next->key - node->key) > 0) {
      node->next = n->next;
      n->next = node;
      return;
    }
    n = n->next;
  }
  n->next = node;
}

// insert to waiting list
void insert_to_wait(Node **head, Node *const node, FILE* stream) {
  Node *new_head = *head;
  
  if (new_head == NULL) {
    *head = node;
    LOG_DBG(stream, DBG_PARSER, "Head is null, first node in the waiting...\n");/**/
    return;
  }
  else {
    node->next = new_head;
    *head = node;
    LOG_DBG(stream, DBG_PARSER, "Next waiting node at the first place...\n");/**/
    return;
  }
}

// insert end of list
void insert_last_node(Node **head, Node *const node) {
  Node *n = *head;
  if (n == NULL) {
    *head = node;
    return;
  }
  while (n->next != NULL) {
    n = n->next;
  }
  n->next = node;
}

// insert head of list
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
Node *pop_first_node(Node **head) {
  Node *n = *head;
  if (n == NULL) {
    return NULL;
  }
  *head = n->next;
  return n;
  /* 
  if (!head) return NULL;
  assert(*head != NULL);
  Node *n = *head;
  if (!n) {
    return NULL;
  }
  *head = n->next;
  return n;
  */  
}
  