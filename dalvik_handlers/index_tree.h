////////////////////////////////////////////////////////////////////////////////////
//
//      FILE:           index_tree.h
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

#ifndef INDEX_TREE_H_
#define INDEX_TREE_H_

#include <linux/rbtree.h>
#include <linux/list.h>

struct index_tree_node {
	struct rb_node node;
	unsigned long long index;
};

struct dict_tree_node {
	struct rb_node node;
	char letter;
	unsigned int leaf;
	struct rb_root subtree;
} __attribute__((aligned(sizeof(long))));

#define RB_NODE (struct rb_node) { 0, NULL, NULL, }
#define RB_DICT_NODE	(struct dict_tree_node) { RB_NODE, 0, 0, RB_ROOT, }

#ifdef __INDEX_TREE_IMPORT__
extern "C"
{
#endif

	struct index_tree_node* index_search( struct rb_root *root, unsigned long long index );
	int index_insert( struct rb_root *root, unsigned long long index );
	void index_erase ( struct rb_root *root, unsigned long long index );
	void index_empty_tree ( struct rb_root *root );
	struct rb_root* dict_search ( struct rb_root *root, const char* str );
	struct rb_root* dict_insert ( struct rb_root* root, const char* str );
	void dict_erase ( struct rb_root *root, const char* str );
	void dict_empty_tree ( struct rb_root *root );
	int  dict_is_empty ( struct rb_root *root );

#ifdef __INDEX_TREE_IMPORT__
}
#endif




#endif /* INDEX_TREE_H_ */
