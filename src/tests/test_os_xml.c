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

static void nodecat(XML_NODE node, OS_XML *xml, char *buffer) {
	int i = 0;
	/* write node */
	while(node[i])
	{
		strncat(buffer, "<", 1);
		ck_assert_ptr_ne(node[i]->element, NULL);
		strncat(buffer, node[i]->element, strlen(node[i]->element));
		/* write attributes */
		if(node[i]->attributes)
		{
			ck_assert_ptr_ne(node[i]->values, NULL);
			int j = 0;
			while(node[i]->attributes[j])
			{
				strncat(buffer, " ", 1);
				ck_assert_ptr_ne(node[i]->values[j], NULL);
				strncat(buffer, node[i]->attributes[j], strlen(node[i]->attributes[j]));
				strncat(buffer, "=", 1);
				strncat(buffer, "\"", 1);
				strncat(buffer, node[i]->values[j], strlen(node[i]->values[j]));
				strncat(buffer, "\"", 1);
				j++;
			}
			ck_assert_ptr_eq(node[i]->values[j], NULL);
		}
		else
		{
			ck_assert_ptr_eq(node[i]->values, NULL);
		}
		strncat(buffer, ">", 1);
		ck_assert_ptr_ne(node[i]->content, NULL);
		strncat(buffer, node[i]->content, strlen(node[i]->content));

		/* write children */
		XML_NODE child = OS_GetElementsbyNode(xml, node[i]);
		if(child != NULL)
		{
			nodecat(child, xml, buffer);
			OS_ClearNode(child);
		}

		/* close node */
		strncat(buffer, "</", 2);
		strncat(buffer, node[i]->element, strlen(node[i]->element));
		strncat(buffer, ">", 1);
		i++;
	}
}

static void assert_os_xml_eq_str(OS_XML *xml, const char *xml_str)
{
	XML_NODE node = OS_GetElementsbyNode(xml, NULL);
	if(node == NULL)
	{
		ck_assert_str_eq(xml_str, "");
		return;
	}

	char *buffer = malloc(6144 * sizeof(char));
	buffer[0] = '\0';
	nodecat(node, xml, buffer);
	OS_ClearNode(node);

	ck_assert_str_eq(buffer, xml_str);
}

static void assert_os_xml_eq(const char *parse_str, const char *xml_str)
{
	char xml_file_name[256];
	create_xml_file(parse_str, xml_file_name, 256);
	OS_XML xml;
	ck_assert_int_eq(OS_ReadXML(xml_file_name, &xml), 0);
	ck_assert_int_eq(OS_ApplyVariables(&xml), 0);
	assert_os_xml_eq_str(&xml, xml_str);

	OS_ClearXML(&xml);
	unlink(xml_file_name);
}

START_TEST(test_simplenodes)
{
	assert_os_xml_eq("", "");
	assert_os_xml_eq("<root></root>", "<root></root>");
	assert_os_xml_eq("<root/>", "<root></root>");
}
END_TEST


START_TEST(test_multiplenodes)
{
	assert_os_xml_eq(
			"<root1></root1>"
			"<root2></root2>"
			"<root3/>",
			"<root1></root1>"
			"<root2></root2>"
			"<root3></root3>");
}
END_TEST

START_TEST(test_children)
{
	assert_os_xml_eq(
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
			"<root1>"
			"<child1></child1>"
			"</root1>"
			"<root2>"
			"<child1></child1>"
			"<child2></child2>"
			"<child3>"
			"<child3.1></child3.1>"
			"</child3>"
			"</root2>"
			"<root3></root3>");
}
END_TEST


START_TEST(test_attributes)
{
	assert_os_xml_eq(
			"<root attr1=\"test\" attr2=\"1\"></root>",
			"<root attr1=\"test\" attr2=\"1\"></root>");
}
END_TEST

START_TEST(test_variables)
{
	assert_os_xml_eq(
			"<var name=\"var1\">value1</var>"
			"<var name=\"var2\">value2</var>"
			"<root attr1=\"$var1\" attr2=\"1\">$var2</root>"
			"<root attr1=\"blah$var1\" attr2=\"1\">blah$var2</root>"
			"<root attr1=\"blah$var1$var2 blah\" attr2=\"1\">blah$var2$var1 blah</root>",
			"<root attr1=\"value1\" attr2=\"1\">value2</root>"
			"<root attr1=\"blahvalue1\" attr2=\"1\">blahvalue2</root>"
			"<root attr1=\"blahvalue1value2 blah\" attr2=\"1\">blahvalue2value1 blah</root>");
}
END_TEST


Suite *test_os_xml_suite(void)
{
	Suite *s = suite_create("os_xml");

	/* Core test case */
	TCase *tc_core = tcase_create("Core");
	tcase_add_test(tc_core, test_simplenodes);
	tcase_add_test(tc_core, test_multiplenodes);
	tcase_add_test(tc_core, test_children);
	tcase_add_test(tc_core, test_attributes);
	tcase_add_test(tc_core, test_variables);
	//TODO: test comments, \, <, >, $
	suite_add_tcase(s, tc_core);

	return (s);
}
