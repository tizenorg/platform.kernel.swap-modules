////////////////////////////////////////////////////////////////////////////////////
//
//      FILE:           index_tree.c
//
//      DESCRIPTION:	fast search implementation based on linux kernel rb_tree
//
//      SEE ALSO:
//      AUTHOR:         L.Astakhov
//      COMPANY NAME:   Samsung Research Center in Moscow
//      DEPT NAME:      Advanced Software Group
//      CREATED:        2011.06.07
//      VERSION:        1.0
//      REVISION DATE:  2011.06.07
//
////////////////////////////////////////////////////////////////////////////////////

#define __INDEX_TREE_EXPORT__

#include "index_tree.h"
#include <allocator.h>

// ===================================================================
//
// Index tree
//
// ===================================================================


struct index_tree_node* index_search(struct rb_root *root, unsigned long long index)
{
	struct rb_node *node = root->rb_node;

	while (node) {
		struct index_tree_node *data = container_of(node, struct index_tree_node, node);

		if (index < data->index)
			node = node->rb_left;
		else if (index > data->index)
			node = node->rb_right;
		else
			return data;
	}
	return NULL;
}

int index_insert_node(struct rb_root *root, struct index_tree_node *data)
{
	struct rb_node **new = &(root->rb_node), *parent = NULL;

	/* Figure out where to put new node */
	while (*new) {
		struct index_tree_node *this = container_of(*new, struct index_tree_node, node);

		parent = *new;

		if ( data->index < this->index )
			new = &((*new)->rb_left);
		else if ( data->index > this->index )
			new = &((*new)->rb_right);
		else
			return 0;
	}

	/* Add new node and rebalance tree. */
	rb_link_node(&data->node, parent, new);
	rb_insert_color(&data->node, root);

	return 1;
}

int index_insert(struct rb_root *root, unsigned long long index)
{
	struct index_tree_node* data = NULL;
	unsigned int size = sizeof (struct index_tree_node);

	data = allocate ( size );
	data->index = index;

	return index_insert_node( root, data );
}

void index_empty_node ( struct rb_node **victim )
{
	struct index_tree_node *this = NULL;

	this = container_of(*victim, struct index_tree_node, node);

	if ( NULL == this )
		return;

	if ( NULL != (*victim)->rb_left )
		index_empty_node( &(*victim)->rb_left );

	if ( NULL != (*victim)->rb_right )
		index_empty_node( &(*victim)->rb_right );

	deallocate ( this );
	*victim = NULL;
}

void index_empty_tree ( struct rb_root *root )
{
	index_empty_node( &root->rb_node );
}

void index_erase ( struct rb_root *root, unsigned long long index )
{
	struct index_tree_node* data = NULL;

	if ( NULL == root )
		return;

	data = index_search ( root, index );

	if ( NULL == data )
		return;

	rb_erase( &data->node, root );
	deallocate ( data );
}

// ===================================================================
//
// Dictionary tree
//
// ===================================================================


struct rb_node** letter_search_node(struct rb_node **node, char letter)
{
	while ( *node )
	{
		struct dict_tree_node *data = container_of(*node, struct dict_tree_node, node);

		if ( letter < data->letter)
			node = &((*node)->rb_left);
		else if ( letter > data->letter )
			node = &((*node)->rb_right);
		else
			return node;
	}

	return node;
}

struct dict_tree_node* letter_subsearch(struct rb_node *node, char letter)
{
	while (node)
	{
		struct dict_tree_node *data = container_of(node, struct dict_tree_node, node);

		if ( letter < data->letter)
			node = node->rb_left;
		else if ( letter > data->letter )
			node = node->rb_right;
		else
			return data;
	}

	return NULL;
}

struct dict_tree_node* letter_search(struct rb_root *root, char letter)
{
	struct rb_node *node = root->rb_node;

	return letter_subsearch ( node, letter );
}

int letter_insert(struct rb_root *root, struct dict_tree_node *data)
{
	struct rb_node *parent = NULL;
	struct rb_node **new = &(root->rb_node);
	struct dict_tree_node *this = NULL;

	/* Figure out where to put new node */
	while (*new) {

		this = container_of(*new, struct dict_tree_node, node);

		parent = *new;

		if ( data->letter < this->letter )
			new = &((*new)->rb_left);
		else if ( data->letter > this->letter )
			new = &((*new)->rb_right);
		else
			return 0;
	}

	/* Add new node and rebalance tree. */
	rb_link_node(&data->node, parent, new);
	rb_insert_color(&data->node, root);

	return 1;
}

struct dict_tree_node* dict_search_node (struct rb_root *root, const char* str)
{
	struct rb_root *begin = root;
	struct dict_tree_node* data = NULL;
	const char* pI = str;

	if ( NULL == pI )
		return NULL;

	do
	{
		data = letter_search ( begin, *pI );

		if ( NULL == data )
			break;

		begin = &data->subtree;

	} while ( *++pI );

	return data;
}

int dict_contains ( struct rb_root *root, const char* str )
{
	struct dict_tree_node* data = NULL;

	data = dict_search_node ( root, str );

	if ( NULL == data )
		return 0;

	return data->leaf;
}

struct rb_root* dict_search (struct rb_root *root, const char* str)
{
	struct dict_tree_node* data = NULL;

	data = dict_search_node ( root, str );

	if ( NULL == data )
		return NULL;

	return &data->subtree;
}

struct rb_root* dict_insert ( struct rb_root* root, const char* str )
{
	struct rb_root *begin = root;
	struct dict_tree_node* data = NULL;
	struct dict_tree_node *node = NULL;

	unsigned int size = sizeof ( struct dict_tree_node );

	const char* pI = str;

	if ( NULL == pI )
		return NULL;

	do
	{
		data = letter_search ( begin, *pI );

		if ( NULL == data )
			break;

		begin = &data->subtree;

	} while ( *++pI );

	if ( 0 == *pI ) // the string is already in
		return begin;

	// part of the string (probably whole string) is not in tree
	do
	{
		node = allocate ( size );
		*node = RB_DICT_NODE;

		node->letter = *pI;
		node->leaf = 0;

		letter_insert ( begin, node );

		begin = &node->subtree;

	}while ( *++pI );

	node->leaf = 1;

	return begin;
}

void dict_erase ( struct rb_root *root, const char* str )
{
	struct dict_tree_node* data = NULL;

	const char* pI = str;

	if ( NULL == pI || 0 == *pI || NULL == root )
		return;

	data = letter_search ( root, *pI );

	if ( NULL == data )
		return;

	dict_erase ( &data->subtree, ++pI );

	if ( NULL != data->subtree.rb_node ) // if subtree is not empty
		return;

	if ( 0 != *pI && data->leaf ) // if not last && it is leaf
		return;

	rb_erase( &data->node, root );
	deallocate ( data );
}

void dict_empty_node ( struct rb_node **victim )
{
	struct dict_tree_node *this = NULL;

	this = container_of(*victim, struct dict_tree_node, node);

	if ( NULL == this )
		return;

	dict_empty_tree ( &this->subtree );

	if ( NULL != (*victim)->rb_left )
		dict_empty_node( &(*victim)->rb_left );

	if ( NULL != (*victim)->rb_right )
		dict_empty_node( &(*victim)->rb_right );

	deallocate ( this );
	*victim = NULL;

}

void dict_empty_tree ( struct rb_root *root )
{
	dict_empty_node( &root->rb_node );
}

int dict_is_empty ( struct rb_root *root )
{
	return ( 0 == root->rb_node );
}
