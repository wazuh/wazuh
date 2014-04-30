/* Copyright (C) 2014 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include <check.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include "../os_xml/os_xml.h"
#include "../os_xml/os_xml_internal.h"

Suite *test_suite(void);

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

    char *buffer = (char *) malloc(6144 * sizeof(char));
    buffer[0] = '\0';
    nodecat(node, xml, buffer);
    OS_ClearNode(node);

    ck_assert_str_eq(buffer, xml_str);

    free(buffer);
}

#define assert_os_xml_eq(PARSE_STR, XML_STR) do { \
    char _ck_xml_file_name[256]; \
    create_xml_file(PARSE_STR, _ck_xml_file_name, 256); \
    OS_XML _ck_xml; \
    ck_assert_int_eq(OS_ReadXML(_ck_xml_file_name, &_ck_xml), 0); \
    ck_assert_int_eq(OS_ApplyVariables(&_ck_xml), 0); \
    assert_os_xml_eq_str(&_ck_xml, XML_STR); \
    OS_ClearXML(&_ck_xml); \
    unlink(_ck_xml_file_name); \
} while (0)

START_TEST(test_simplenodes)
{
    assert_os_xml_eq("", "");
    assert_os_xml_eq("<root></root>", "<root></root>");
    assert_os_xml_eq("<root/>", "<root></root>");
    assert_os_xml_eq("<root />", "<root></root>");
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

START_TEST(test_multiplecontent)
{
    assert_os_xml_eq(
            "<root>"
            "value1"
            "<child/>"
            "</root>",
            "<root><child></child></root>");
    assert_os_xml_eq(
            "<root>"
            "value1"
            "<child/>"
            "value2"
            "</root>",
            "<root>value2<child></child></root>");
}
END_TEST


START_TEST(test_attributes)
{
    assert_os_xml_eq(
            "<root attr1=\"test\" attr2=\"1\"></root>",
            "<root attr1=\"test\" attr2=\"1\"></root>");

    assert_os_xml_eq(
            "<root attr1=\"test\"\nattr2=\"test\"\tattr3=\"test\"></root>",
            "<root attr1=\"test\" attr2=\"test\" attr3=\"test\"></root>");

    assert_os_xml_eq(
            "<root attr1=\"test/test\"></root>",
            "<root attr1=\"test/test\"></root>");

    assert_os_xml_eq(
            "<root attr1=\"test1\"></root><root attr1=\"test2\"></root>",
            "<root attr1=\"test1\"></root><root attr1=\"test2\"></root>");

    assert_os_xml_eq(
            "<root attr1=\"test\"\n\t  \t\n  \n\t  \nattr2=\"test\"></root>",
            "<root attr1=\"test\" attr2=\"test\"></root>");

    assert_os_xml_eq(
            "<root\n\t  \t\n  \n\t  \nattr1=\"test\"></root>",
            "<root attr1=\"test\"></root>");

    assert_os_xml_eq(
            "<root attr1=\n\t  \t\n  \n\t  \n\"test\"></root>",
            "<root attr1=\"test\"></root>");

    assert_os_xml_eq(
            "<root attr=\"test\" />",
            "<root attr=\"test\"></root>");

    assert_os_xml_eq(
            "<root attr=\"test\"/>",
            "<root attr=\"test\"></root>");
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

START_TEST(test_comments)
{
    assert_os_xml_eq(
            "<root1/><!comment!><root2/>",
            "<root1></root1><root2></root2>");
    assert_os_xml_eq(
            "<root1/><!--comment--><root2/>",
            "<root1></root1><root2></root2>");

    assert_os_xml_eq(
            "<root1/><! comment with ! !><root2/>",
            "<root1></root1><root2></root2>");

    assert_os_xml_eq(
            "<root1/><! comment with - --><root2/>",
            "<root1></root1><root2></root2>");
}
END_TEST

START_TEST(test_specialchars)
{
    assert_os_xml_eq(
            "<var name=\"var1\">value1</var>"
            "<root1>\\</root1\\></root1>",
            "<root1>\\</root1\\></root1>");
}
END_TEST

START_TEST(test_linecounter)
{
    char xml_file_name[256];
    create_xml_file("<root1/>\n<root2/>\n<root3/>" , xml_file_name, 256);
    OS_XML xml;
    XML_NODE node;
    ck_assert_int_eq(OS_ReadXML(xml_file_name, &xml), 0);
    ck_assert_int_eq(OS_ApplyVariables(&xml), 0);
    ck_assert_ptr_ne(node = OS_GetElementsbyNode(&xml, NULL), NULL);
    ck_assert_int_eq(xml.ln[0], 1);
    ck_assert_int_eq(xml.ln[1], 2);
    ck_assert_int_eq(xml.ln[2], 3);

    OS_ClearNode(node);
    OS_ClearXML(&xml);
    unlink(xml_file_name);
}
END_TEST

START_TEST(test_invalidfile)
{
    OS_XML xml;
    ck_assert_int_ne(OS_ReadXML("invalid_file.inv", &xml), 0);
    ck_assert_str_eq(xml.err, "XMLERR: File 'invalid_file.inv' not found.");
    ck_assert_int_eq(xml.err_line, 0);

    OS_ClearXML(&xml);
}
END_TEST

START_TEST(test_unclosednode)
{
    char xml_file_name[256];
    create_xml_file("<root>", xml_file_name, 256);
    OS_XML xml;
    ck_assert_int_ne(OS_ReadXML(xml_file_name, &xml), 0);
    ck_assert_str_eq(xml.err, "XMLERR: End of file and some elements were not closed.");
    ck_assert_int_eq(xml.err_line, 1);

    OS_ClearXML(&xml);
    unlink(xml_file_name);
}
END_TEST

START_TEST(test_unclosednode2)
{
    char xml_file_name[256];
    create_xml_file("<root></root2>", xml_file_name, 256);
    OS_XML xml;
    ck_assert_int_ne(OS_ReadXML(xml_file_name, &xml), 0);
    ck_assert_str_eq(xml.err, "XMLERR: Element 'root' not closed.");
    ck_assert_int_eq(xml.err_line, 1);

    OS_ClearXML(&xml);
    unlink(xml_file_name);
}
END_TEST

START_TEST(test_unclosedcomment)
{
    char xml_file_name[256];
    create_xml_file("<!-- comment", xml_file_name, 256);
    OS_XML xml;
    ck_assert_int_ne(OS_ReadXML(xml_file_name, &xml), 0);
    ck_assert_str_eq(xml.err, "XMLERR: Comment not closed.");
    ck_assert_int_eq(xml.err_line, 1);

    OS_ClearXML(&xml);
    unlink(xml_file_name);
}
END_TEST

START_TEST(test_nodenotopened)
{
    char xml_file_name[256];
    create_xml_file("</root>", xml_file_name, 256);
    OS_XML xml;
    ck_assert_int_ne(OS_ReadXML(xml_file_name, &xml), 0);
    ck_assert_str_eq(xml.err, "XMLERR: Element not opened.");
    ck_assert_int_eq(xml.err_line, 1);

    OS_ClearXML(&xml);
    unlink(xml_file_name);
}
END_TEST

START_TEST(test_unclosedattribute)
{
    char xml_file_name[256];
    create_xml_file("<root attr=\"attribute></root>", xml_file_name, 256);
    OS_XML xml;
    ck_assert_int_ne(OS_ReadXML(xml_file_name, &xml), 0);
    ck_assert_str_eq(xml.err, "XMLERR: Attribute 'attr' not closed.");
    ck_assert_int_eq(xml.err_line, 1);

    OS_ClearXML(&xml);
    unlink(xml_file_name);
}
END_TEST

START_TEST(test_unquotedattribute)
{
    char xml_file_name[256];
    create_xml_file("<root attr=attribute></root>", xml_file_name, 256);
    OS_XML xml;
    ck_assert_int_ne(OS_ReadXML(xml_file_name, &xml), 0);
    ck_assert_str_eq(xml.err, "XMLERR: Attribute 'attr' not followed by a \" or '.");
    ck_assert_int_eq(xml.err_line, 1);

    OS_ClearXML(&xml);
    unlink(xml_file_name);
}
END_TEST

START_TEST(test_infiniteattribute)
{
    char xml_file_name[256];
    create_xml_file("<root attr", xml_file_name, 256);
    OS_XML xml;
    ck_assert_int_ne(OS_ReadXML(xml_file_name, &xml), 0);
    ck_assert_str_eq(xml.err, "XMLERR: End of file while reading an attribute.");
    ck_assert_int_eq(xml.err_line, 1);

    OS_ClearXML(&xml);
    unlink(xml_file_name);
}
END_TEST

START_TEST(test_invalidvariablename)
{
    char xml_file_name[256];
    create_xml_file("<var test=\"test\"></var>", xml_file_name, 256);
    OS_XML xml;
    ck_assert_int_eq(OS_ReadXML(xml_file_name, &xml), 0);
    ck_assert_int_ne(OS_ApplyVariables(&xml), 0);
    ck_assert_str_eq(xml.err, "XMLERR: Only \"name\" is allowed as an attribute for a variable.");
    ck_assert_int_eq(xml.err_line, 1);

    OS_ClearXML(&xml);
    unlink(xml_file_name);
}
END_TEST

START_TEST(test_invalidvariable)
{
    char xml_file_name[256];
    char overflow_string[XML_VARIABLE_MAXSIZE + 10];
    memset(overflow_string, 'c', XML_VARIABLE_MAXSIZE + 9);
    overflow_string[XML_VARIABLE_MAXSIZE + 9] = '\0';

    char xml_string[2 * XML_VARIABLE_MAXSIZE];
    snprintf(xml_string, 2 * XML_VARIABLE_MAXSIZE - 1, "<var name=\"%s\">test</var><root/>", overflow_string);
    create_xml_file(xml_string, xml_file_name, 256);
    OS_XML xml;
    ck_assert_int_eq(OS_ReadXML(xml_file_name, &xml), 0);
    ck_assert_int_ne(OS_ApplyVariables(&xml), 0);
    ck_assert_str_eq(xml.err, "XMLERR: Invalid variable name size.");
    ck_assert_int_eq(xml.err_line, 1);

    OS_ClearXML(&xml);
    unlink(xml_file_name);
}
END_TEST

START_TEST(test_invalidvariable2)
{
    char xml_file_name[256];
    char overflow_string[XML_VARIABLE_MAXSIZE + 10];
    memset(overflow_string, 'c', XML_VARIABLE_MAXSIZE + 9);
    overflow_string[XML_VARIABLE_MAXSIZE + 9] = '\0';

    char xml_string[3 * XML_VARIABLE_MAXSIZE];
    snprintf(xml_string, 3 * XML_VARIABLE_MAXSIZE - 1, "<var name=\"%s\">test</var><test>$%s</test>", overflow_string, overflow_string);
    create_xml_file(xml_string, xml_file_name, 256);
    OS_XML xml;
    ck_assert_int_eq(OS_ReadXML(xml_file_name, &xml), 0);
    ck_assert_int_ne(OS_ApplyVariables(&xml), 0);
    ck_assert_str_eq(xml.err, "XMLERR: Invalid variable name size.");
    ck_assert_int_eq(xml.err_line, 1);

    OS_ClearXML(&xml);
    unlink(xml_file_name);
}
END_TEST

START_TEST(test_unknownvariable)
{
    char xml_file_name[256];
    create_xml_file("<var name=\"test\">content</var><root>$var</root>", xml_file_name, 256);
    OS_XML xml;
    ck_assert_int_eq(OS_ReadXML(xml_file_name, &xml), 0);
    ck_assert_int_ne(OS_ApplyVariables(&xml), 0);
    ck_assert_str_eq(xml.err, "XMLERR: Unknown variable: 'var'.");
    ck_assert_int_eq(xml.err_line, 1);

    OS_ClearXML(&xml);
    unlink(xml_file_name);
}
END_TEST

START_TEST(test_infiniteattribute2)
{
    char xml_file_name[256];
    create_xml_file("<root attr=", xml_file_name, 256);
    OS_XML xml;
    ck_assert_int_ne(OS_ReadXML(xml_file_name, &xml), 0);
    ck_assert_str_eq(xml.err, "XMLERR: Attribute 'attr' not followed by a \" or '.");
    ck_assert_int_eq(xml.err_line, 1);

    OS_ClearXML(&xml);
    unlink(xml_file_name);
}
END_TEST

START_TEST(test_invalidattributestart)
{
    char xml_file_name[256];
    create_xml_file("<root attr=  test\"test\"/>", xml_file_name, 256);
    OS_XML xml;
    ck_assert_int_ne(OS_ReadXML(xml_file_name, &xml), 0);
    ck_assert_str_eq(xml.err, "XMLERR: Attribute 'attr' not followed by a \" or '.");
    ck_assert_int_eq(xml.err_line, 1);

    OS_ClearXML(&xml);
    unlink(xml_file_name);
}
END_TEST

START_TEST(test_invalidattributeclosing)
{
    char xml_file_name[256];
    create_xml_file("<root attr=''", xml_file_name, 256);
    OS_XML xml;
    ck_assert_int_ne(OS_ReadXML(xml_file_name, &xml), 0);
    ck_assert_str_eq(xml.err, "XMLERR: Bad attribute closing for 'attr'=''.");
    ck_assert_int_eq(xml.err_line, 1);

    OS_ClearXML(&xml);
    unlink(xml_file_name);
}
END_TEST

START_TEST(test_invalidattributeclosing2)
{
    char xml_file_name[256];
    create_xml_file("<root attr='test'test/>", xml_file_name, 256);
    OS_XML xml;
    ck_assert_int_ne(OS_ReadXML(xml_file_name, &xml), 0);
    ck_assert_str_eq(xml.err, "XMLERR: Bad attribute closing for 'attr'='test'.");
    ck_assert_int_eq(xml.err_line, 1);

    OS_ClearXML(&xml);
    unlink(xml_file_name);
}
END_TEST

START_TEST(test_infiniteattribute3)
{
    char xml_file_name[256];
    create_xml_file("<root attr='", xml_file_name, 256);
    OS_XML xml;
    ck_assert_int_ne(OS_ReadXML(xml_file_name, &xml), 0);
    ck_assert_str_eq(xml.err, "XMLERR: End of file while reading an attribute.");
    ck_assert_int_eq(xml.err_line, 1);

    OS_ClearXML(&xml);
    unlink(xml_file_name);
}
END_TEST

START_TEST(test_duplicateattribute)
{
    char xml_file_name[256];
    create_xml_file("<root attr='test' attr2='test' attr='test123'></root>", xml_file_name, 256);
    OS_XML xml;
    ck_assert_int_ne(OS_ReadXML(xml_file_name, &xml), 0);
    ck_assert_str_eq(xml.err, "XMLERR: Attribute 'attr' already defined.");
    ck_assert_int_eq(xml.err_line, 1);

    OS_ClearXML(&xml);
    unlink(xml_file_name);
}
END_TEST

START_TEST(test_noattributevalue)
{
    char xml_file_name[256];
    create_xml_file("<root attr></root>", xml_file_name, 256);
    OS_XML xml;
    ck_assert_int_ne(OS_ReadXML(xml_file_name, &xml), 0);
    ck_assert_str_eq(xml.err, "XMLERR: Attribute 'attr' has no value.");
    ck_assert_int_eq(xml.err_line, 1);

    OS_ClearXML(&xml);
    unlink(xml_file_name);
}
END_TEST

START_TEST(test_noattributevalue2)
{
    char xml_file_name[256];
    create_xml_file("<root attr attr2='test'></root>", xml_file_name, 256);
    OS_XML xml;
    ck_assert_int_ne(OS_ReadXML(xml_file_name, &xml), 0);
    ck_assert_str_eq(xml.err, "XMLERR: Attribute 'attr' has no value.");
    ck_assert_int_eq(xml.err_line, 1);

    OS_ClearXML(&xml);
    unlink(xml_file_name);
}
END_TEST

//TODO
/*START_TEST(test_unknownvariable)
{
    char xml_file_name[256];
    create_xml_file("<root>$var</root>", xml_file_name, 256);
    OS_XML xml;
    ck_assert_int_eq(OS_ReadXML(xml_file_name, &xml), 0);
    ck_assert_int_ne(OS_ApplyVariables(&xml), 0);
    ck_assert_str_eq(xml.err, "XML_ERR: Unknown variable: var");
    ck_assert_int_eq(xml.err_line, 0);

    OS_ClearXML(&xml);
    unlink(xml_file_name);
}
END_TEST*/

START_TEST(test_oselementsexists)
{
    char xml_file_name[256];
    create_xml_file("<root></root><root1/><root/>", xml_file_name, 256);
    OS_XML xml;
    ck_assert_int_eq(OS_ReadXML(xml_file_name, &xml), 0);
    ck_assert_int_eq(OS_ApplyVariables(&xml), 0);
    ck_assert_int_eq(OS_RootElementExist(&xml, "root"), 2);
    ck_assert_int_eq(OS_RootElementExist(&xml, "root1"), 1);
    ck_assert_int_eq(OS_RootElementExist(&xml, "root2"), 0);

    OS_ClearXML(&xml);
    unlink(xml_file_name);
}
END_TEST

START_TEST(test_osgetonecontentforelement)
{
    char xml_file_name[256];
    create_xml_file("<root><child>test</child><child>test2</child><child2>test</child2></root>", xml_file_name, 256);
    OS_XML xml;
    ck_assert_int_eq(OS_ReadXML(xml_file_name, &xml), 0);
    ck_assert_int_eq(OS_ApplyVariables(&xml), 0);
    const char *xml_path1[] = { "root", "child", NULL };
    const char *xml_path2[] = { "root", "child2", NULL };
    const char *xml_path3[] = { "root", "child3", NULL };
    char *content1, *content2;
    ck_assert_str_eq(content1 = OS_GetOneContentforElement(&xml, xml_path1), "test");
    ck_assert_str_eq(content2 = OS_GetOneContentforElement(&xml, xml_path2), "test");
    ck_assert_ptr_eq(OS_GetOneContentforElement(&xml, xml_path3), NULL);

    free(content1);
    free(content2);
    OS_ClearXML(&xml);
    unlink(xml_file_name);
}
END_TEST

static void assert_ox_xml_write_eq(const char *xml_str_old, const char *xml_str_new,const char **xml_path, const char *oldval, const char *newval)
{
    char xml_in_file_name[256];
    create_xml_file(xml_str_old, xml_in_file_name, 256);
    char xml_out_file_name[256];
    create_xml_file("", xml_out_file_name, 256);

    ck_assert_int_eq(OS_WriteXML(xml_in_file_name, xml_out_file_name, xml_path, oldval, newval), 0);

    OS_XML xml;
    ck_assert_int_eq(OS_ReadXML(xml_out_file_name, &xml), 0);
    ck_assert_int_eq(OS_ApplyVariables(&xml), 0);
    assert_os_xml_eq_str(&xml, xml_str_new);

    OS_ClearXML(&xml);
    unlink(xml_in_file_name);
    unlink(xml_out_file_name);
}

START_TEST(test_oswritexml_success)
{
    const char *xml_path[] = { "root", "child", NULL };
    assert_ox_xml_write_eq(
            "<root><child>test</child></root>",
            "<root><child>test_new</child></root>",
            xml_path, "test", "test_new");

    assert_ox_xml_write_eq(
            "<root><child>test</child></root>",
            "<root><child>test</child></root>",
            xml_path, "test", "test");

    assert_ox_xml_write_eq(
            "<root><child></child></root>",
            "<root><child>test</child></root>",
            xml_path, "test", "test");

    assert_ox_xml_write_eq(
                "<root2><child></child></root2>",
                "<root2><child></child></root2><root>\n <child>test</child></root>",
                xml_path, NULL, "test");
}
END_TEST

START_TEST(test_oswritexml_failures)
{
    char xml_in_file_name[256];
    create_xml_file("<root><child>test</child></root>", xml_in_file_name, 256);
    char xml_out_file_name[256];
    create_xml_file("", xml_out_file_name, 256);
    const char *xml_path[] = { "root", "child", NULL };

    ck_assert_int_eq(OS_WriteXML("invalid", xml_out_file_name, xml_path, "test", "test_new"), XMLW_NOIN);
    ck_assert_int_eq(OS_WriteXML(xml_in_file_name, "??invalid<<!!\"\"//\\\\", xml_path, "test", "test_new"), XMLW_NOOUT);

    unlink(xml_in_file_name);
    unlink(xml_out_file_name);
}
END_TEST

START_TEST(test_osgetattributecontent)
{
    char xml_file_name[256];
    create_xml_file("<root attr=\"value\" attr2=\"value1\"></root>", xml_file_name, 256);
    OS_XML xml;
    ck_assert_int_eq(OS_ReadXML(xml_file_name, &xml), 0);
    ck_assert_int_eq(OS_ApplyVariables(&xml), 0);
    const char *xml_path1[] = { "root", NULL };
    const char *xml_path2[] = { NULL };
    char *content1, *content2, *content3, *content4;
    ck_assert_str_eq(content1 = OS_GetAttributeContent(&xml, xml_path1, "attr"), "value");
    ck_assert_str_eq(content2 = OS_GetAttributeContent(&xml, xml_path1, "attr2"), "value1");
    ck_assert_str_eq(content3 = OS_GetAttributeContent(&xml, xml_path1, "attr3"), "");
    ck_assert_str_eq(content4 = OS_GetAttributeContent(&xml, xml_path1, NULL), "");
    ck_assert_ptr_eq(OS_GetAttributeContent(&xml, xml_path2, NULL), NULL);


    free(content1);
    free(content2);
    free(content3);
    free(content4);
    OS_ClearXML(&xml);
    unlink(xml_file_name);
}
END_TEST

START_TEST(test_osgetcontents)
{
    char xml_file_name[256];
    create_xml_file("<root>value</root><root>value2</root><root2>value</root2>", xml_file_name, 256);
    OS_XML xml;
    ck_assert_int_eq(OS_ReadXML(xml_file_name, &xml), 0);
    ck_assert_int_eq(OS_ApplyVariables(&xml), 0);
    const char *xml_path1[] = { "root", NULL };
    const char *xml_path2[] = { "root2", NULL };
    char **content1, **content2;
    ck_assert_ptr_ne(content1 = OS_GetContents(&xml, xml_path1), NULL);
    ck_assert_str_eq(content1[0], "value");
    ck_assert_str_eq(content1[1], "value2");
    ck_assert_ptr_eq(content1[2], NULL);

    ck_assert_ptr_ne(content2 = OS_GetContents(&xml, xml_path2), NULL);
    ck_assert_str_eq(content2[0], "value");
    ck_assert_ptr_eq(content2[1], NULL);

    ck_assert_ptr_eq(OS_GetContents(&xml, NULL), NULL);

    int i = 0;
    while(content1[i])
        free(content1[i++]);
    free(content1);

    i = 0;
    while(content2[i])
        free(content2[i++]);
    free(content2);
    OS_ClearXML(&xml);
    unlink(xml_file_name);
}
END_TEST

START_TEST(test_osgetelementcontent)
{
    char xml_file_name[256];
    create_xml_file("<root>value</root>", xml_file_name, 256);
    OS_XML xml;
    ck_assert_int_eq(OS_ReadXML(xml_file_name, &xml), 0);
    ck_assert_int_eq(OS_ApplyVariables(&xml), 0);
    const char *xml_path[] = { "root", NULL };
    char **content;
    ck_assert_ptr_ne(content = OS_GetElementContent(&xml, xml_path), NULL);
    ck_assert_str_eq(content[0], "value");
    ck_assert_ptr_eq(content[1], NULL);

    int i = 0;
    while(content[i])
        free(content[i++]);
    free(content);
    OS_ClearXML(&xml);
    unlink(xml_file_name);
}
END_TEST

START_TEST(test_osgetelements)
{
    char xml_file_name[256];
    create_xml_file("<root><child1/><child2/></root>", xml_file_name, 256);
    OS_XML xml;
    ck_assert_int_eq(OS_ReadXML(xml_file_name, &xml), 0);
    ck_assert_int_eq(OS_ApplyVariables(&xml), 0);
    const char *xml_path[] = { "root", NULL };
    char **content1, **content2;
    ck_assert_ptr_ne(content1 = OS_GetElements(&xml, xml_path), NULL);
    ck_assert_str_eq(content1[0], "child1");
    ck_assert_str_eq(content1[1], "child2");
    ck_assert_ptr_eq(content1[2], NULL);
    ck_assert_ptr_ne(content2 = OS_GetElements(&xml, NULL), NULL);
    ck_assert_str_eq(content2[0], "root");
    ck_assert_ptr_eq(content2[1], NULL);
    const char *xml_path2[] = { NULL };
    ck_assert_ptr_eq(OS_GetElements(&xml,  xml_path2), NULL);

    int i = 0;
    while(content1[i])
        free(content1[i++]);
    free(content1);
    i = 0;
    while(content2[i])
        free(content2[i++]);
    free(content2);
    OS_ClearXML(&xml);
    unlink(xml_file_name);
}
END_TEST

START_TEST(test_osgetattributes)
{
    char xml_file_name[256];
    create_xml_file("<root attr1=\"1\" attr2=\"2\"></root>", xml_file_name, 256);
    OS_XML xml;
    ck_assert_int_eq(OS_ReadXML(xml_file_name, &xml), 0);
    ck_assert_int_eq(OS_ApplyVariables(&xml), 0);
    const char *xml_path[] = { "root", NULL };
    char **content;
    ck_assert_ptr_ne(content = OS_GetAttributes(&xml, xml_path), NULL);
    ck_assert_str_eq(content[0], "attr1");
    ck_assert_str_eq(content[1], "attr2");
    ck_assert_ptr_eq(content[2], NULL);

    int i = 0;
    while(content[i])
        free(content[i++]);
    free(content);
    OS_ClearXML(&xml);
    unlink(xml_file_name);
}
END_TEST

START_TEST(test_osclearnode)
{
    OS_ClearNode(NULL);
}
END_TEST

START_TEST(test_stringoverflow)
{
    char xml_file_name[256];
    char overflow_string[XML_MAXSIZE + 10];
    memset(overflow_string, 'c', XML_MAXSIZE + 9);
    overflow_string[XML_MAXSIZE + 9] = '\0';

    char xml_string[2 * XML_MAXSIZE];
    snprintf(xml_string, 2 * XML_MAXSIZE - 1, "<%s/>", overflow_string);
    create_xml_file(xml_string, xml_file_name, 256);
    OS_XML xml;
    ck_assert_int_ne(OS_ReadXML(xml_file_name, &xml), 0);
    ck_assert_str_eq(xml.err, "XMLERR: String overflow.");
    ck_assert_int_eq(xml.err_line, 1);

    OS_ClearXML(&xml);
    unlink(xml_file_name);
}
END_TEST

START_TEST(test_stringoverflow2)
{
    char xml_file_name[256];
    char overflow_string[XML_MAXSIZE + 10];
    memset(overflow_string, 'c', XML_MAXSIZE + 9);
    overflow_string[XML_MAXSIZE + 9] = '\0';

    char xml_string[2 * XML_MAXSIZE];
    snprintf(xml_string, 2 * XML_MAXSIZE - 1, "<test>%s</test>", overflow_string);
    create_xml_file(xml_string, xml_file_name, 256);
    OS_XML xml;
    ck_assert_int_ne(OS_ReadXML(xml_file_name, &xml), 0);
    ck_assert_str_eq(xml.err, "XMLERR: String overflow.");
    ck_assert_int_eq(xml.err_line, 1);

    OS_ClearXML(&xml);
    unlink(xml_file_name);
}
END_TEST

START_TEST(test_stringoverflow3)
{
    char xml_file_name[256];
    char overflow_string[XML_MAXSIZE + 10];
    memset(overflow_string, 'c', XML_MAXSIZE + 9);
    overflow_string[XML_MAXSIZE + 9] = '\0';

    char xml_string[2 * XML_MAXSIZE];
    snprintf(xml_string, 2 * XML_MAXSIZE - 1, "<test %s=\"test\">test</test>", overflow_string);
    create_xml_file(xml_string, xml_file_name, 256);
    OS_XML xml;
    ck_assert_int_ne(OS_ReadXML(xml_file_name, &xml), 0);
    ck_assert_str_eq(xml.err, "XMLERR: Overflow attempt at attribute 'cccccccccccccccccccc'.");
    ck_assert_int_eq(xml.err_line, 1);

    OS_ClearXML(&xml);
    unlink(xml_file_name);
}
END_TEST

START_TEST(test_stringoverflow4)
{
    char xml_file_name[256];
    char overflow_string[XML_MAXSIZE + 10];
    memset(overflow_string, 'c', XML_MAXSIZE + 9);
    overflow_string[XML_MAXSIZE + 9] = '\0';

    char xml_string[2 * XML_MAXSIZE];
    snprintf(xml_string, 2 * XML_MAXSIZE - 1, "<test test=\"%s\">test</test>", overflow_string);
    create_xml_file(xml_string, xml_file_name, 256);
    OS_XML xml;
    ck_assert_int_ne(OS_ReadXML(xml_file_name, &xml), 0);
    ck_assert_str_eq(xml.err, "XMLERR: Overflow attempt at attribute 'test'.");
    ck_assert_int_eq(xml.err_line, 1);

    OS_ClearXML(&xml);
    unlink(xml_file_name);
}
END_TEST

Suite *test_suite(void)
{
    Suite *s = suite_create("os_xml");

    /* Core test case */
    TCase *tc_core = tcase_create("Core");
    tcase_add_test(tc_core, test_simplenodes);
    tcase_add_test(tc_core, test_multiplenodes);
    tcase_add_test(tc_core, test_multiplecontent);
    tcase_add_test(tc_core, test_children);
    tcase_add_test(tc_core, test_attributes);
    tcase_add_test(tc_core, test_variables);
    tcase_add_test(tc_core, test_comments);
    tcase_add_test(tc_core, test_specialchars);
    tcase_add_test(tc_core, test_linecounter);
    tcase_add_test(tc_core, test_invalidfile);
    tcase_add_test(tc_core, test_unclosednode);
    tcase_add_test(tc_core, test_unclosednode2);
    tcase_add_test(tc_core, test_unclosedcomment);
    tcase_add_test(tc_core, test_nodenotopened);
    tcase_add_test(tc_core, test_unclosedattribute);
    tcase_add_test(tc_core, test_infiniteattribute);
    tcase_add_test(tc_core, test_unquotedattribute);
    tcase_add_test(tc_core, test_invalidvariablename);
    tcase_add_test(tc_core, test_invalidvariable);
    tcase_add_test(tc_core, test_invalidvariable2);
    tcase_add_test(tc_core, test_unknownvariable);
    tcase_add_test(tc_core, test_infiniteattribute2);
    tcase_add_test(tc_core, test_invalidattributestart);
    tcase_add_test(tc_core, test_invalidattributeclosing);
    tcase_add_test(tc_core, test_invalidattributeclosing2);
    tcase_add_test(tc_core, test_infiniteattribute3);
    tcase_add_test(tc_core, test_duplicateattribute);
    tcase_add_test(tc_core, test_noattributevalue);
    tcase_add_test(tc_core, test_noattributevalue2);
    tcase_add_test(tc_core, test_oselementsexists);
    tcase_add_test(tc_core, test_osgetonecontentforelement);
    tcase_add_test(tc_core, test_oswritexml_success);
    tcase_add_test(tc_core, test_oswritexml_failures);
    tcase_add_test(tc_core, test_osgetattributecontent);
    tcase_add_test(tc_core, test_osgetcontents);
    tcase_add_test(tc_core, test_osgetelementcontent);
    tcase_add_test(tc_core, test_osgetelements);
    tcase_add_test(tc_core, test_osgetattributes);
    tcase_add_test(tc_core, test_osclearnode);
    tcase_add_test(tc_core, test_stringoverflow);
    tcase_add_test(tc_core, test_stringoverflow2);
    tcase_add_test(tc_core, test_stringoverflow3);
    tcase_add_test(tc_core, test_stringoverflow4);
    suite_add_tcase(s, tc_core);

    return (s);
}

int main(void)
{
    Suite *s = test_suite();
    SRunner *sr = srunner_create(s);
    srunner_run_all(sr, CK_NORMAL);
    int number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return ((number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE);
}
