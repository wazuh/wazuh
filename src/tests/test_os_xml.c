/* Copyright (C) 2014 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include "test_os_xml.h"

#include "../os_xml/os_xml.h"

static void create_xml_file(const char *str, char file_name[], size_t length)
{
	strncpy(file_name, "/tmp/tmp_file-XXXXXX", length);
	int fd = mkstemp(file_name);

	write(fd, str, strlen(str));
	close(fd);
}


START_TEST(test_singleroot)
{
	char xml_file_name[256];
	create_xml_file(
			"<root></root>",
			xml_file_name, 256);
	OS_XML xml;
	XML_NODE node;
	ck_assert_int_eq(OS_ReadXML(xml_file_name, &xml), 0);
	ck_assert_int_eq(OS_ApplyVariables(&xml), 0);
	ck_assert_ptr_ne(node = OS_GetElementsbyNode(&xml, NULL), NULL);

	ck_assert_ptr_ne(node[0], NULL);
	ck_assert_str_eq(node[0]->element, "root");
	ck_assert_str_eq(node[0]->content, "");
	ck_assert_ptr_eq(node[0]->attributes, NULL);
	ck_assert_ptr_eq(node[0]->values, NULL);
	ck_assert_ptr_eq(node[1], NULL);

	OS_ClearNode(node);
	OS_ClearXML(&xml);
	unlink(xml_file_name);
}
END_TEST


START_TEST(test_multipleroot)
{
	char xml_file_name[256];
	create_xml_file(
			"<root1></root1>"
			"<root2></root2>"
			"<root3/>",
			xml_file_name, 256);
	OS_XML xml;
	XML_NODE node;
	ck_assert_int_eq(OS_ReadXML(xml_file_name, &xml), 0);
	ck_assert_int_eq(OS_ApplyVariables(&xml), 0);
	ck_assert_ptr_ne(node = OS_GetElementsbyNode(&xml, NULL), NULL);

	ck_assert_ptr_ne(node[0], NULL);
	ck_assert_str_eq(node[0]->element, "root1");
	ck_assert_str_eq(node[0]->content, "");
	ck_assert_ptr_eq(node[0]->attributes, NULL);
	ck_assert_ptr_eq(node[0]->values, NULL);
	ck_assert_str_eq(node[1]->element, "root2");
	ck_assert_str_eq(node[1]->content, "");
	ck_assert_ptr_eq(node[1]->attributes, NULL);
	ck_assert_ptr_eq(node[1]->values, NULL);
	ck_assert_str_eq(node[2]->element, "root3");
	ck_assert_str_eq(node[2]->content, "");
	ck_assert_ptr_eq(node[2]->attributes, NULL);
	ck_assert_ptr_eq(node[2]->values, NULL);
	ck_assert_ptr_eq(node[3], NULL);

	OS_ClearNode(node);
	OS_ClearXML(&xml);
	unlink(xml_file_name);
}
END_TEST

START_TEST(test_children)
{
	char xml_file_name[256];
	create_xml_file(
			"<root1>"
			"<child1></child1>"
			"</root1>"
			"<root2>"
			"<child1></child1>"
			"<child2/>"
			"<child3>"
			"<child3.1></child3.1>"
			"</child3>"
			"</root2>"
			"<root3></root3>",
			xml_file_name, 256);
	OS_XML xml;
	XML_NODE node, child, grandchild;
	ck_assert_int_eq(OS_ReadXML(xml_file_name, &xml), 0);
	ck_assert_int_eq(OS_ApplyVariables(&xml), 0);
	ck_assert_ptr_ne(node = OS_GetElementsbyNode(&xml, NULL), NULL);

	ck_assert_ptr_ne(node[0], NULL);
	ck_assert_str_eq(node[0]->element, "root1");
	ck_assert_str_eq(node[0]->content, "");
	ck_assert_ptr_eq(node[0]->attributes, NULL);
	ck_assert_ptr_eq(node[0]->values, NULL);

	ck_assert_ptr_ne(child = OS_GetElementsbyNode(&xml, node[0]), NULL);
	ck_assert_ptr_ne(child[0], NULL);
	ck_assert_str_eq(child[0]->element, "child1");
	ck_assert_str_eq(child[0]->content, "");
	ck_assert_ptr_eq(child[0]->attributes, NULL);
	ck_assert_ptr_eq(child[0]->values, NULL);
	ck_assert_ptr_eq(child[1], NULL);
	OS_ClearNode(child);


	ck_assert_str_eq(node[1]->element, "root2");
	ck_assert_str_eq(node[1]->content, "");
	ck_assert_ptr_eq(node[1]->attributes, NULL);
	ck_assert_ptr_eq(node[1]->values, NULL);

	ck_assert_ptr_ne(child = OS_GetElementsbyNode(&xml, node[1]), NULL);
	ck_assert_ptr_ne(child[0], NULL);
	ck_assert_str_eq(child[0]->element, "child1");
	ck_assert_str_eq(child[0]->content, "");
	ck_assert_ptr_eq(child[0]->attributes, NULL);
	ck_assert_ptr_eq(child[0]->values, NULL);

	ck_assert_ptr_ne(child[1], NULL);
	ck_assert_str_eq(child[1]->element, "child2");
	ck_assert_str_eq(child[1]->content, "");
	ck_assert_ptr_eq(child[1]->attributes, NULL);
	ck_assert_ptr_eq(child[1]->values, NULL);

	ck_assert_ptr_ne(child[2], NULL);
	ck_assert_str_eq(child[2]->element, "child3");
	ck_assert_str_eq(child[2]->content, "");
	ck_assert_ptr_eq(child[2]->attributes, NULL);
	ck_assert_ptr_eq(child[2]->values, NULL);

	ck_assert_ptr_ne(grandchild = OS_GetElementsbyNode(&xml, child[2]), NULL);
	ck_assert_ptr_ne(grandchild[0], NULL);
	ck_assert_str_eq(grandchild[0]->element, "child3.1");
	ck_assert_str_eq(grandchild[0]->content, "");
	ck_assert_ptr_eq(grandchild[0]->attributes, NULL);
	ck_assert_ptr_eq(grandchild[0]->values, NULL);
	ck_assert_ptr_eq(grandchild[1], NULL);
	OS_ClearNode(grandchild);

	ck_assert_ptr_eq(child[3], NULL);
	OS_ClearNode(child);

	ck_assert_str_eq(node[2]->element, "root3");
	ck_assert_str_eq(node[2]->content, "");
	ck_assert_ptr_eq(node[2]->attributes, NULL);
	ck_assert_ptr_eq(node[2]->values, NULL);
	ck_assert_ptr_eq(OS_GetElementsbyNode(&xml, node[2]), NULL);

	ck_assert_ptr_eq(node[3], NULL);


	OS_ClearNode(node);
	OS_ClearXML(&xml);
	unlink(xml_file_name);
}
END_TEST


START_TEST(test_attributes)
{
	char xml_file_name[256];
	create_xml_file(
			"<root attr1=\"test\" attr2=\"1\"></root>",
			xml_file_name, 256);
	OS_XML xml;
	XML_NODE node;
	ck_assert_int_eq(OS_ReadXML(xml_file_name, &xml), 0);
	ck_assert_int_eq(OS_ApplyVariables(&xml), 0);
	ck_assert_ptr_ne(node = OS_GetElementsbyNode(&xml, NULL), NULL);

	ck_assert_ptr_ne(node[0], NULL);
	ck_assert_str_eq(node[0]->element, "root");
	ck_assert_str_eq(node[0]->content, "");
	ck_assert_ptr_ne(node[0]->attributes, NULL);
	ck_assert_str_eq(node[0]->attributes[0], "attr1");
	ck_assert_str_eq(node[0]->attributes[1], "attr2");
	ck_assert_ptr_eq(node[0]->attributes[2], NULL);
	ck_assert_ptr_ne(node[0]->values, NULL);
	ck_assert_str_eq(node[0]->values[0], "test");
	ck_assert_str_eq(node[0]->values[1], "1");
	ck_assert_ptr_eq(node[0]->values[2], NULL);
	ck_assert_ptr_eq(node[1], NULL);

	OS_ClearNode(node);
	OS_ClearXML(&xml);
	unlink(xml_file_name);
}
END_TEST

START_TEST(test_variables)
{
	char xml_file_name[256];
	create_xml_file(
			"<var name=\"var1\">value1</var>"
			"<var name=\"var2\">value2</var>"
			"<root attr1=\"$var1\" attr2=\"1\">$var2</root>"
			"<root attr1=\"blah$var1\" attr2=\"1\">blah$var2</root>"
			"<root attr1=\"blah$var1$var2 blah\" attr2=\"1\">blah$var2$var1 blah</root>",
			xml_file_name, 256);
	OS_XML xml;
	XML_NODE node;
	ck_assert_int_eq(OS_ReadXML(xml_file_name, &xml), 0);
	ck_assert_int_eq(OS_ApplyVariables(&xml), 0);
	ck_assert_ptr_ne(node = OS_GetElementsbyNode(&xml, NULL), NULL);

	ck_assert_ptr_ne(node[0], NULL);
	ck_assert_str_eq(node[0]->element, "root");
	ck_assert_str_eq(node[0]->content, "value2");
	ck_assert_ptr_ne(node[0]->attributes, NULL);
	ck_assert_str_eq(node[0]->attributes[0], "attr1");
	ck_assert_str_eq(node[0]->attributes[1], "attr2");
	ck_assert_ptr_eq(node[0]->attributes[2], NULL);
	ck_assert_ptr_ne(node[0]->values, NULL);
	ck_assert_str_eq(node[0]->values[0], "value1");
	ck_assert_str_eq(node[0]->values[1], "1");
	ck_assert_ptr_eq(node[0]->values[2], NULL);

	ck_assert_ptr_ne(node[1], NULL);
	ck_assert_str_eq(node[1]->element, "root");
	ck_assert_str_eq(node[1]->content, "blahvalue2");
	ck_assert_ptr_ne(node[1]->attributes, NULL);
	ck_assert_str_eq(node[1]->attributes[0], "attr1");
	ck_assert_str_eq(node[1]->attributes[1], "attr2");
	ck_assert_ptr_eq(node[1]->attributes[2], NULL);
	ck_assert_ptr_ne(node[1]->values, NULL);
	ck_assert_str_eq(node[1]->values[0], "blahvalue1");
	ck_assert_str_eq(node[1]->values[1], "1");
	ck_assert_ptr_eq(node[1]->values[2], NULL);

	ck_assert_ptr_ne(node[2], NULL);
	ck_assert_str_eq(node[2]->element, "root");
	ck_assert_str_eq(node[2]->content, "blahvalue2value1 blah");
	ck_assert_ptr_ne(node[2]->attributes, NULL);
	ck_assert_str_eq(node[2]->attributes[0], "attr1");
	ck_assert_str_eq(node[2]->attributes[1], "attr2");
	ck_assert_ptr_eq(node[2]->attributes[2], NULL);
	ck_assert_ptr_ne(node[2]->values, NULL);
	ck_assert_str_eq(node[2]->values[0], "blahvalue1value2 blah");
	ck_assert_str_eq(node[2]->values[1], "1");
	ck_assert_ptr_eq(node[2]->values[2], NULL);

	ck_assert_ptr_eq(node[3], NULL);

	OS_ClearNode(node);
	OS_ClearXML(&xml);
	unlink(xml_file_name);
}
END_TEST


Suite *test_os_xml_suite(void)
{
	Suite *s = suite_create("os_xml");

	/* Core test case */
	TCase *tc_core = tcase_create("Core");
	tcase_add_test(tc_core, test_singleroot);
	tcase_add_test(tc_core, test_multipleroot);
	tcase_add_test(tc_core, test_children);
	tcase_add_test(tc_core, test_attributes);
	tcase_add_test(tc_core, test_variables);
	//TODO: test comments, \, <, >, $
	suite_add_tcase(s, tc_core);

	return (s);
}
