#include <stdio.h>
#include "ausearch-int.h"

int main(void)
{
	int i = 0;
	ilist e;
	int_node *node;

	ilist_create(&e);

	// This first test checks to see if list is 
	// created in a numeric order
	ilist_add_if_uniq(&e, 6, 0);
	ilist_add_if_uniq(&e, 5, 0);
	ilist_add_if_uniq(&e, 7, 0);
	ilist_add_if_uniq(&e, 1, 0);
	ilist_add_if_uniq(&e, 8, 0);
	ilist_add_if_uniq(&e, 2, 0);
	ilist_add_if_uniq(&e, 9, 0);
	ilist_add_if_uniq(&e, 0, 0);
	ilist_add_if_uniq(&e, 4, 0);
	ilist_add_if_uniq(&e, 3, 0);

	ilist_first(&e);
	do {
		node = ilist_get_cur(&e);
		if (i != node->num) {
			printf("Test failed - i:%d != num:%d\n", i, node->num);
			return 1;
		}
		i++;
	} while ((node = ilist_next(&e)));

	ilist_clear(&e);
	puts("starting sort test");

	// Now test to see if the sort function works
	// Fill the list exactly backwards
	ilist_add_if_uniq(&e, 3, 0);
	ilist_add_if_uniq(&e, 3, 0);
	ilist_add_if_uniq(&e, 4, 0);
	ilist_add_if_uniq(&e, 3, 0);
	ilist_add_if_uniq(&e, 4, 0);
	ilist_add_if_uniq(&e, 2, 0);
	ilist_add_if_uniq(&e, 4, 0);
	ilist_add_if_uniq(&e, 2, 0);
	ilist_add_if_uniq(&e, 4, 0); 
	ilist_add_if_uniq(&e, 1, 0);

	ilist_sort_by_hits(&e);

	i = 0;
	ilist_first(&e);
	do {
		node = ilist_get_cur(&e);
		if (node->hits != (4-i)) {
			printf("Sort test failed - i:%d != ihits:%d\n", i, node->hits);
			return 1;
		}
		i++;
	} while ((node = ilist_next(&e)));
	
	ilist_clear(&e);

	printf("ilist tests passed\n");
	return 0;
}

