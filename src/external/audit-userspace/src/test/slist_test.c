#include <stdio.h>
#include <string.h>
#include "ausearch-string.h"

slist s;

int print_list(void)
{
	int cnt = 0;
	slist_first(&s);
	do {
		snode *cur = slist_get_cur(&s);
		if (cur) {
			cnt++;
			printf("%s\n", cur->str);
		}
	} while (slist_next(&s));
	return cnt;
}

int main(void)
{
	snode n, *node;
	int rc, i = 0;

	slist_create(&s);

	// This first test checks to see if list is
	// created in a numeric order
	slist_add_if_uniq(&s, "test1");
	slist_add_if_uniq(&s, "test2");
	slist_first(&s);
	slist_add_if_uniq(&s, "test3");
	puts("should be 3");
	rc = print_list();
	if (s.cnt != 3 || rc !=3) {
		puts("test count is wrong");
		return 1;
	}

	n.str = strdup("test4");
	n.key = NULL;
	n.hits = 1;
	slist_append(&s, &n);
	puts("should add a #4");
	rc = print_list();
	if (s.cnt != 4 || rc != 4) {
		puts("test count is wrong");
		return 1;
	}

	slist_add_if_uniq(&s, "test2");
	puts("should be same");
	rc = print_list();
	if (s.cnt != 4 || rc != 4) {
		puts("test count is wrong");
		return 1;
	}

	slist_clear(&s);
	puts("should be empty");
	rc = print_list();	
	if (s.cnt != 0 || rc != 0) {
		puts("test count is wrong");
		return 1;
	}
	puts("starting sort test");

	// Now test to see if the sort function works
	// Fill the list exactly backwards
	slist_add_if_uniq(&s, "test3");
	slist_add_if_uniq(&s, "test3");
	slist_add_if_uniq(&s, "test4");
	slist_add_if_uniq(&s, "test3");
	slist_add_if_uniq(&s, "test4");
	slist_add_if_uniq(&s, "test2");
	slist_add_if_uniq(&s, "test4");
	slist_add_if_uniq(&s, "test2");
	slist_add_if_uniq(&s, "test4");
	slist_add_if_uniq(&s, "test1");

	slist_sort_by_hits(&s);
	slist_first(&s);
	do {
		node = slist_get_cur(&s);
		if (node->hits != (4-i)) {
			printf("Sort test failed - i:%d != hits:%u\n", i, node->hits);
			return 1;
		}
		i++;
	} while ((node = slist_next(&s)));
	puts("sort test passes");

	slist_clear(&s);
	
	return 0;
}

