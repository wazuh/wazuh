/**
 * @file rbtree_op.c
 * @brief RB tree data structure definition
 * @date 2019-08-21
 *
 * @copyright Copyright (c) 2019 Wazuh, Inc.
 */

/*
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <shared.h>

#ifdef WAZUH_UNIT_TESTING
/* Replace assert with mock_assert */
extern void mock_assert(const int result, const char* const expression,
                        const char * const file, const int line);
#undef assert
#define assert(expression) \
    mock_assert((int)(expression), #expression, __FILE__, __LINE__);
#endif

void customAssert(bool expression);
void customAssert(bool expression) {
    if (expression == FALSE) {
        exit(1);
    }
}

/* Private functions **********************************************************/

#define grandparent parent->parent

/**
 * @brief Create and initialize a red-black tree node
 *
 * @param key Data key. It will be duplicated.
 * @param value Data value.
 * @return Pointer to a newly created node.
 */

static rb_node * rb_init(const char * key, void * value) {
    rb_node * node;
    os_calloc(1, sizeof(rb_node), node);
    os_strdup(key, node->key);
    node->value = value;
    node->color = RB_RED;
    return node;
}

/**
 * @brief Free a red-black subtree
 * @param node Pointer to a red-black tree node.
 * @param dispose Pointer to function to dispose an element.
 * @post If dispose is not NULL, the value is freed.
 */

static void rb_destroy(rb_node * node, void (*dispose)(void *)) {
    if (node->left != NULL) {
        rb_destroy(node->left, dispose);
    }

    if (node->right != NULL) {
        rb_destroy(node->right, dispose);
    }

    free(node->key);

    if (node->value != NULL && dispose != NULL) {
        dispose(node->value);
    }

    free(node);
}

/**
 * @brief Find a node from a subtree
 *
 * @param node Pointer to a red-black tree node.
 * @param key Data key (search criteria).
 * @return Pointer to the node storing the key, if found.
 * @retval NULL Key not found.
 */

rb_node * rb_get(rb_node * node, const char * key) {
    while (node != NULL) {
        int cmp = strcmp(key, node->key);

        if (cmp == 0) {
            break;
        }

        node = cmp < 0 ? node->left : node->right;
    }

    return node;
}

/**
 * @brief Get the node with the minimum key from a subtree
 *
 * Return the leftmost node of the subtree.
 *
 * @param node Pointer to a red-black tree node.
 * @return Pointer to the node storing the minimum key.
 */

static rb_node * rb_min(rb_node * node) {
    rb_node * t;
    for (t = node; t->left != NULL; t = t->left);
    return t;
}

/**
 * @brief Get the node with the maximum key from a subtree
 *
 * Return the rightmost node of the subtree.
 *
 * @param node Pointer to a red-black tree node.
 * @return Pointer to the node storing the maximum key.
 */

static rb_node * rb_max(rb_node * node) {
    rb_node * t;
    for (t = node; t->right != NULL; t = t->right);
    return t;
}

/**
 * @brief Get the uncle of a node
 *
 * @param node Pointer to a red-black tree node.
 * @return Pointer to the sibling of node's parent.
 */

static rb_node * rb_uncle(rb_node * node) {
    rb_node * gp;
    return (node->parent && (gp = node->grandparent)) ? (node->parent == gp->left) ? gp->right : gp->left : NULL;
}

/**
 * @brief Rotate a subtree to left
 *
 * @param tree Pointer to a red-black tree.
 * @param node Pointer to the pivot node.
 */

static void rb_rotate_left(rb_tree * tree, rb_node * node) {
    rb_node * t = node->right;

    if (node->parent == NULL) {
        tree->root = t;
    } else {
        if (node == node->parent->left) {
            node->parent->left = t;
        } else {
            node->parent->right = t;
        }
    }

    if (t->left != NULL) {
        t->left->parent = node;
    }

    node->right = t->left;
    t->left = node;
    t->parent = node->parent;
    node->parent = t;
}

/**
 * @brief Rotate a subtree to right
 *
 * @param tree Pointer to a red-black tree.
 * @param node Pointer to the pivot node.
 */

static void rb_rotate_right(rb_tree * tree, rb_node * node) {
    rb_node * t = node->left;

    if (node->parent == NULL) {
        tree->root = t;
    } else {
        if (node == node->parent->left) {
            node->parent->left = t;
        } else {
            node->parent->right = t;
        }
    }

    if (t->right != NULL) {
        t->right->parent = node;
    }

    node->left = t->right;
    t->right = node;
    t->parent = node->parent;
    node->parent = t;
}

/**
 * @brief Balance a tree after an insertion
 *
 * @param tree Pointer to a red-black tree.
 * @param node Pointer to the node that was inserted.
 */

static void rb_balance_insert(rb_tree * tree, rb_node * node) {
    while (node->parent && node->parent->color == RB_RED) {
        rb_node * uncle = rb_uncle(node);

        if (uncle != NULL && uncle->color == RB_RED) {
            node->parent->color = RB_BLACK;
            uncle->color = RB_BLACK;
            node->grandparent->color = RB_RED;

            node = node->grandparent;
        } else {
            if (node->parent == node->grandparent->left) {
                if (node == node->parent->right) {
                    node = node->parent;
                    rb_rotate_left(tree, node);
                }

                node->parent->color = RB_BLACK;
                node->grandparent->color = RB_RED;

                rb_rotate_right(tree, node->grandparent);
            } else {
                if (node == node->parent->left) {
                    node = node->parent;
                    rb_rotate_right(tree, node);
                }

                node->parent->color = RB_BLACK;
                node->grandparent->color = RB_RED;

                rb_rotate_left(tree, node->grandparent);
            }
        }
    }

    tree->root->color = RB_BLACK;
}

/**
 * @brief Balance a tree after a deletion
 *
 * @param tree Pointer to the red-black tree.
 * @param node Pointer to the node that was deleted.
 * @param parent Pointer to the parent of node.
 */

static void rb_balance_delete(rb_tree * tree, rb_node * node, rb_node * parent) {
    while (parent != NULL && (node == NULL || node->color == RB_BLACK)) {
        if (node == parent->left) {
            rb_node * sibling = parent->right;

            customAssert(sibling != NULL);

            if (sibling->color == RB_RED) {
                // Case 1: sibling is red

                sibling->color = RB_BLACK;
                parent->color = RB_RED;
                rb_rotate_left(tree, parent);
                sibling = parent->right;
            }

            if (sibling->color == RB_BLACK && (sibling->left == NULL || sibling->left->color == RB_BLACK) && (sibling->right == NULL || sibling->right->color == RB_BLACK)) {
                // Case 2: sibling is black and both nephews are black

                sibling->color = RB_RED;
                node = parent;
                parent = parent->parent;

            } else {
                if (sibling->right == NULL || sibling->right->color == RB_BLACK) {
                    // Case 3: Sibling is black, left nephew is red and right nephew is black

                    sibling->left->color = RB_BLACK;
                    sibling->color = RB_RED;
                    rb_rotate_right(tree, sibling);
                    sibling = parent->right;
                }

                customAssert(sibling->right != NULL);
                // Case 4: Sibling is black, right nephew is red

                sibling->color = parent->color;
                parent->color = RB_BLACK;
                sibling->right->color = RB_BLACK;
                rb_rotate_left(tree, parent);

                break;
            }
        } else {
            rb_node * sibling = parent->left;

            assert(sibling != NULL);

            if (sibling->color == RB_RED) {
                // Case 1b: sibling is red

                sibling->color = RB_BLACK;
                parent->color = RB_RED;
                rb_rotate_right(tree, parent);
                sibling = parent->left;
            }

            if (sibling->color == RB_BLACK && (sibling->left == NULL || sibling->left->color == RB_BLACK) && (sibling->right == NULL || sibling->right->color == RB_BLACK)) {
                // Case 2b: sibling is black and both nephews are black

                sibling->color = RB_RED;
                node = parent;
                parent = parent->parent;
            } else {
                if (sibling->left == NULL || sibling->left->color == RB_BLACK) {
                    // Case 3b: Sibling is black, left nephew is red and right nephew is black

                    sibling->right->color = RB_BLACK;
                    sibling->color = RB_RED;
                    rb_rotate_left(tree, sibling);
                    sibling = parent->left;
                }

                customAssert(sibling->left != NULL);
                // Case 4b: Sibling is black, right nephew is red

                sibling->color = parent->color;
                parent->color = RB_BLACK;
                sibling->left->color = RB_BLACK;
                rb_rotate_right(tree, parent);

                break;
            }
        }
    }

    if (node != NULL) {
        node->color = RB_BLACK;
    }
}

/**
 * @brief Get all the keys in a subtree
 *
 * @param node Pointer to a red-black tree node.
 * @param array Pointer to the target string array.
 * @param size[in,out] Pointer to the current size of the array.
 * @pre array is expected to be size cells long.
 * @post array is reallocated to size+2 cells long.
 * @post array is no longer valid after calling this function.
 * @return Newly allocated null-terminated array of keys.
 */

static char ** rb_keys(rb_node * node, char ** array, unsigned * size) {
    if (node->left != NULL) {
        array = rb_keys(node->left, array, size);
    }

    os_realloc(array, sizeof(char *) * (*size + 2), array);
    os_strdup(node->key, array[(*size)++]);

    if (node->right != NULL) {
        array = rb_keys(node->right, array, size);
    }

    return array;
}

/**
 * @brief Get all the keys from the subtree within a range
 *
 * @param node Pointer to a red-black tree node.
 * @param min Minimum key.
 * @param max Maximum key.
 * @param array Pointer to the target string array.
 * @param size[in,out] Pointer to the current size of the array.
 * @pre array is expected to be size cells long.
 * @post array is reallocated to size+2 cells long.
 * @post array is no longer valid after calling this function.
 * @return Newly allocated null-terminated array of keys.
 */

static char ** rb_range(rb_node * node, const char * min, const char * max, char ** array, unsigned * size) {
    int cmp_min = strcmp(node->key, min);
    int cmp_max = strcmp(node->key, max);

    if (node->left != NULL && cmp_min > 0) {
        // node > min
        array = rb_range(node->left, min, max, array, size);
    }

    if (cmp_min >= 0 && cmp_max <= 0) {
        // min <= node <= max
        os_realloc(array, sizeof(char *) * (*size + 2), array);
        os_strdup(node->key, array[(*size)++]);
    }

    if (node->right != NULL && cmp_max < 0) {
        // node < min
        array = rb_range(node->right, min, max, array, size);
    }

    return array;
}

/**
 * @brief Get the black depth of a red-black subtree
 *
 * The black depth of a node is the number of black nodes from it to any leaf,
 * including null leafs (that are black) and excluding the node itself.
 *
 * This function is test-oriented: it checks that all possible paths from the
 * root to every leaf matches, and returns the length of this path.
 *
 * @param node Pointer to a red-black tree node.
 * @return Number of black nodes from this node.
 * @retval -1 The subtree is unbalanced. This would mean a bug.
 */

static int rb_black_depth(rb_node * node) {
    if (node == NULL) {
        return 1;
    }

    int d_left = rb_black_depth(node->left);
    int d_right = rb_black_depth(node->right);

    if (d_left != d_right) {
        return -1;
    }

    return d_left + (node->color == RB_BLACK);
}

/**
 * @brief Get the size of a subtree
 *
 * This function is recursive: 1 + rb_size(left subtree) + rb_size(right subtree).
 *
 * @param node Pointer to a red-black tree node.
 * @return Number of nodes in the subtree.
 */

unsigned rb_size(rb_node * node) {
    return (node->left ? rb_size(node->left) : 0) + 1 + (node->right ? rb_size(node->right) : 0);
}

/* Public functions ***********************************************************/

// Create a red-black tree

rb_tree * rbtree_init() {
    rb_tree * tree;
    os_calloc(1, sizeof(rb_tree), tree);
    return tree;
}

// Free a red-black tree

void rbtree_destroy(rb_tree * tree) {
    if (tree == NULL) {
        return;
    }

    if (tree->root != NULL) {
        rb_destroy(tree->root, tree->dispose);
    }

    free(tree);
}

// Set free function to dispose elements

void rbtree_set_dispose(rb_tree * tree, void (*dispose)(void *)) {
    tree->dispose = dispose;
}

// Insert a key-value in the tree

void * rbtree_insert(rb_tree * tree, const char * key, void * value) {
    assert(tree != NULL);
    assert(key != NULL);

    rb_node * node = rb_init(key, value);
    rb_node * parent = NULL;
    int cmp;

    for (rb_node * t = tree->root; t != NULL; t = cmp < 0 ? t->left : t->right) {
        parent = t;
        cmp = strcmp(key, t->key);

        if (cmp == 0) {
            // Duplicate key. Do not dispose value.
            rb_destroy(node, NULL);
            return NULL;
        }
    }

    if (parent == NULL) {
        tree->root = node;
    } else if (cmp < 0) {
        parent->left = node;
    } else {
        parent->right = node;
    }

    node->parent = parent;
    rb_balance_insert(tree, node);

    return value;
}

// Update the value of an existing key

void * rbtree_replace(rb_tree * tree, const char * key, void * value) {
    assert(tree != NULL);
    assert(key != NULL);

    rb_node * node = rb_get(tree->root, key);

    if (node == NULL) {
        return NULL;
    }

    if (node->value && tree->dispose) {
        tree->dispose(node->value);
    }

    node->value = value;

    return value;
}

// Retrieve a value from the tree

void * rbtree_get(const rb_tree * tree, const char * key) {
    assert(tree != NULL);
    assert(key != NULL);

    rb_node * node = rb_get(tree->root, key);
    return node ? node->value : NULL;
}

// Remove a value from the tree

int rbtree_delete(rb_tree * tree, const char * key) {
    assert(tree != NULL);
    assert(key != NULL);

    rb_node * node = rb_get(tree->root, key);

    if (node == NULL) {
        return 0;
    }

    // Succesor: node that will be actually deleted
    rb_node * s = (node->left != NULL && node->right != NULL) ? rb_min(node->right) : node;
    rb_node * t = (s->left != NULL) ? s->left : s->right;

    if (s->parent == NULL) {
        tree->root = t;
    } else if (s == s->parent->left) {
        s->parent->left = t;
    } else {
        s->parent->right = t;
    }

    if (t != NULL) {
        t->parent = s->parent;
    }

    free(node->key);

    if (node->value && tree->dispose) {
        tree->dispose(node->value);
    }

    if (node != s) {
        // Copy successor into node

        node->key = s->key;
        node->value = s->value;
    }

    if (s->color == RB_BLACK) {
        rb_balance_delete(tree, t, s->parent);
    }

    free(s);
    return 1;
}

// Get the minimum key in the tree

const char * rbtree_minimum(const rb_tree * tree) {
    assert(tree != NULL);
    return tree->root ? rb_min(tree->root)->key : NULL;
}

// Get the maximum key in the tree

const char * rbtree_maximum(const rb_tree * tree) {
    assert(tree != NULL);
    return tree->root ? rb_max(tree->root)->key : NULL;
}

// Get all the keys in the tree

char ** rbtree_keys(const rb_tree * tree) {
    assert(tree != NULL);

    unsigned size = 0;
    char ** array;

    os_malloc(sizeof(char *), array);

    if (tree->root != NULL) {
        array = rb_keys(tree->root, array, &size);
    }

    array[size] = NULL;
    return array;
}

// Get all the keys from the tree within a range

char ** rbtree_range(const rb_tree * tree, const char * min, const char * max) {
    assert(tree != NULL);
    assert(min != NULL);
    assert(max != NULL);

    unsigned size = 0;
    char ** array;

    os_malloc(sizeof(char *), array);

    if (tree->root != NULL) {
        array = rb_range(tree->root, min, max, array, &size);
    }

    array[size] = NULL;
    return array;
}

// Get the black depth of a tree

int rbtree_black_depth(const rb_tree * tree) {
    assert(tree != NULL);

    if (tree->root == NULL) {
        return 0;
    }

    if (tree->root->color == RB_RED) {
        return -1;
    }

    int d_left = rb_black_depth(tree->root->left);
    int d_right = rb_black_depth(tree->root->right);

    return (d_left == -1 || d_right == -1 || d_left != d_right) ? -1 : d_left;
}

// Get the size of the tree

unsigned rbtree_size(const rb_tree * tree) {
    assert(tree != NULL);

    return tree->root ? rb_size(tree->root) : 0;
}

// Check whether the tree is empty

int rbtree_empty(const rb_tree * tree) {
    assert(tree != NULL);

    return tree->root == NULL;
}
