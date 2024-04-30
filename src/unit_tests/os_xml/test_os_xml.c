/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>
#include <stdbool.h>

#include "../../headers/shared.h"
#include "../../os_xml/os_xml.h"
#include "../os_xml/os_xml_internal.h"
#include "../wrappers/common.h"
#include "../../headers/defs.h"

// Struct
typedef struct test_struct {
    OS_XML xml;
    XML_NODE node;
    char xml_file_name[256];
    char xml_out_file_name[256];
    char *buffer;
    char *content1;
    char *content2;
    char *content3;
    char *content4;
    char **content5;
    char **content6;
} test_struct_t;

// Setup / Teardown
static int test_setup(void **state) {
    test_struct_t *init_data = NULL;
    os_calloc(1,sizeof(test_struct_t), init_data);
    os_calloc(OS_SIZE_6144, sizeof(char), init_data->buffer);

    init_data->buffer[0] = '\0';

    *state = init_data;
    return OS_SUCCESS;
}

static int test_teardown(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    os_free(data->buffer);

    if(data->content1 != NULL) {
        os_free(data->content1);
    }
    if(data->content2 != NULL) {
        os_free(data->content2);
    }
    if(data->content3 != NULL) {
        os_free(data->content3);
    }
    if(data->content4 != NULL) {
        os_free(data->content4);
    }

    if(data->content5 != NULL) {
        int i = 0;
        while (data->content5[i]) {
            os_free(data->content5[i]);
            i++;
        }
        os_free(data->content5);
    }

    if(data->content6 != NULL) {
        int i = 0;
        while (data->content6[i]) {
            os_free(data->content6[i]);
            i++;
        }
        os_free(data->content6);
    }

    OS_ClearNode(data->node);
    OS_ClearXML(&data->xml);

    unlink(data->xml_file_name);
    unlink(data->xml_out_file_name);

    os_free(data);

    return OS_SUCCESS;
}

// Tests
static void create_xml_file(const char *str, char file_name[], size_t length) {
    strncpy(file_name, "/tmp/tmp_file-XXXXXX", length);
    int fd = mkstemp(file_name);

    write(fd, str, strlen(str));
    close(fd);
}

static int nodecat(XML_NODE node, OS_XML *xml, char *buffer) {
    int i = 0;

    // write node
    while (node[i]) {
        assert_non_null(node[i]->element);
        strcat(buffer, "<");
        strncat(buffer, node[i]->element, strlen(node[i]->element));
        // write attributes
        if (node[i]->attributes) {
            assert_non_null(node[i]->values);
            int j = 0;
            while (node[i]->attributes[j]) {
                strcat(buffer, " ");
                assert_non_null(node[i]->values[j]);
                strncat(buffer, node[i]->attributes[j], strlen(node[i]->attributes[j]));
                strcat(buffer, "=");
                strcat(buffer, "\"");
                strncat(buffer, node[i]->values[j], strlen(node[i]->values[j]));
                strcat(buffer, "\"");
                j++;
            }
            assert_null(node[i]->values[j]);
        } else {
            assert_null(node[i]->values);
        }
        strcat(buffer, ">");
        assert_non_null(node[i]->content);
        strncat(buffer, node[i]->content, strlen(node[i]->content));

        // write children
        XML_NODE child = OS_GetElementsbyNode(xml, node[i]);
        if (child != NULL) {
            nodecat(child, xml, buffer);
            OS_ClearNode(child);
        }

        // close node
        strcat(buffer, "</");
        strncat(buffer, node[i]->element, strlen(node[i]->element));
        strcat(buffer, ">");
        i++;
    }

    return 1;
}

void assert_os_xml_eq_str(OS_XML *xml, const char *xml_str, char *buffer) {
    XML_NODE node = OS_GetElementsbyNode(xml, NULL);
    if (node == NULL) {
        assert_string_equal(xml_str, "");
        return;
    }
    nodecat(node, xml, buffer);
    OS_ClearNode(node);

    assert_string_equal(buffer, xml_str);
}

void assert_os_xml_eq(test_struct_t *data, char *parse_str, char *xml_str){
    create_xml_file(parse_str, data->xml_file_name, 256);
    assert_int_equal(OS_ReadXML(data->xml_file_name, &data->xml), 0);
    assert_int_equal(OS_ApplyVariables(&data->xml), 0);
    assert_os_xml_eq_str(&data->xml, xml_str, data->buffer);
}

void assert_ox_xml_write_eq( test_struct_t *data,
                            const char *xml_str_old,
                            const char *xml_str_new,
                            const char **xml_path,
                            const char *oldval,
                            const char *newval) {

    create_xml_file(xml_str_old, data->xml_file_name, 256);
    create_xml_file("", data->xml_out_file_name, 256);
    assert_int_equal(OS_WriteXML(data->xml_file_name, data->xml_out_file_name, xml_path, oldval, newval), 0);
    assert_int_equal(OS_ReadXML(data->xml_out_file_name, &data->xml), 0);
    assert_int_equal(OS_ApplyVariables(&data->xml), 0);
    assert_os_xml_eq_str(&data->xml, xml_str_new, data->buffer);

}

void test_simple_nodes1(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    char *parse_str = "";
    char *xml_str = "";

    assert_os_xml_eq(data, parse_str, xml_str);
}

void test_simple_nodes2(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    char *parse_str = "<root></root>";
    char *xml_str = "<root></root>";

    assert_os_xml_eq(data, parse_str, xml_str);
}

void test_simple_nodes3(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    char *parse_str = "<root/>";
    char *xml_str = "<root></root>";

    assert_os_xml_eq(data, parse_str, xml_str);
}

void test_simple_nodes4(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    char *parse_str = "<root />";
    char *xml_str = "<root></root>";

    assert_os_xml_eq(data, parse_str, xml_str);
}

void test_simple_nodes5(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    char *parse_str = "<root/{>";

    create_xml_file(parse_str, data->xml_file_name, 256);
    assert_int_equal(OS_ReadXML(data->xml_file_name, &data->xml), OS_INVALID);
}

void test_multiple_nodes(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    char *parse_str = "<root1></root1>""<root2></root2>""<root3/>";
    char *xml_str = "<root1></root1>""<root2></root2>""<root3></root3>";

    assert_os_xml_eq(data, parse_str, xml_str);
}

void test_children(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    char *parse_str =   "<root1>"
                        "<child1></child1>"
                        "</root1>"
                        "<root2>"
                        "<child1></child1>"
                        "<child2/>"
                        "<child3>"
                        "<child3.1></child3.1>"
                        "</child3>"
                        "</root2>"
                        "<root3></root3>";

    char *xml_str = "<root1>"
                    "<child1></child1>"
                    "</root1>"
                    "<root2>"
                    "<child1></child1>"
                    "<child2></child2>"
                    "<child3>"
                    "<child3.1></child3.1>"
                    "</child3>"
                    "</root2>"
                    "<root3></root3>";

    assert_os_xml_eq(data, parse_str, xml_str);
}

void test_multiple_content(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    char *parse_str =   "<root>"
                        "value1"
                        "<child/>"
                        "value2"
                        "</root>";
    char *xml_str = "<root>value2<child></child></root>";

    assert_os_xml_eq(data, parse_str, xml_str);
}

void test_attributes1(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    char *parse_str = "<root attr1=\"test\" attr2=\"1\"></root>";
    char *xml_str = "<root attr1=\"test\" attr2=\"1\"></root>";

    assert_os_xml_eq(data, parse_str, xml_str);
}

void test_attributes2(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    char *parse_str = "<root attr1=\"test\"\nattr2=\"test\"\tattr3=\"test\"></root>";
    char *xml_str = "<root attr1=\"test\" attr2=\"test\" attr3=\"test\"></root>";

    assert_os_xml_eq(data, parse_str, xml_str);
}

void test_attributes3(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    char *parse_str = "<root attr1=\"test/test\"></root>";
    char *xml_str = "<root attr1=\"test/test\"></root>";

    assert_os_xml_eq(data, parse_str, xml_str);
}

void test_attributes4(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    char *parse_str = "<root attr1=\"test1\"></root><root attr1=\"test2\"></root>";
    char *xml_str = "<root attr1=\"test1\"></root><root attr1=\"test2\"></root>";

    assert_os_xml_eq(data, parse_str, xml_str);
}

void test_attributes5(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    char *parse_str = "<root attr1=\"test\"\n\t  \t\n  \n\t  \nattr2=\"test\"></root>";
    char *xml_str = "<root attr1=\"test\" attr2=\"test\"></root>";

    assert_os_xml_eq(data, parse_str, xml_str);
}

void test_attributes6(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    char *parse_str = "<root\n\t  \t\n  \n\t  \nattr1=\"test\"></root>";
    char *xml_str = "<root attr1=\"test\"></root>";

    assert_os_xml_eq(data, parse_str, xml_str);
}

void test_attributes7(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    char *parse_str = "<root attr1=\n\t  \t\n  \n\t  \n\"test\"></root>";
    char *xml_str = "<root attr1=\"test\"></root>";

    assert_os_xml_eq(data, parse_str, xml_str);
}

void test_attributes8(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    char *parse_str = "<root attr=\"test\" />";
    char *xml_str = "<root attr=\"test\"></root>";

    assert_os_xml_eq(data, parse_str, xml_str);
}

void test_attributes9(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    char *parse_str = "<root attr=\"test\"/>";
    char *xml_str = "<root attr=\"test\"></root>";

    assert_os_xml_eq(data, parse_str, xml_str);
}

void test_variables(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    char *parse_str =   "<var name=\"var1\">value1</var>"
                        "<var name=\"var2\">value2</var>"
                        "<root attr1=\"$var1\" attr2=\"1\">$var2</root>"
                        "<root attr1=\"blah$var1\" attr2=\"1\">blah$var2</root>"
                        "<root attr1=\"blah$var1$var2 blah\" attr2=\"1\">blah$var2$var1 blah</root>";

    char *xml_str = "<root attr1=\"value1\" attr2=\"1\">value2</root>"
                    "<root attr1=\"blahvalue1\" attr2=\"1\">blahvalue2</root>"
                    "<root attr1=\"blahvalue1value2 blah\" attr2=\"1\">blahvalue2value1 blah</root>";

    assert_os_xml_eq(data, parse_str, xml_str);
}

void test_comments1(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    char *parse_str = "<root1/><!comment!><root2/>";
    char *xml_str = "<root1></root1><root2></root2>";

    assert_os_xml_eq(data, parse_str, xml_str);
}

void test_comments2(void **state) {

    test_struct_t *data  = (test_struct_t *)*state;
    char *parse_str = "<root1/><!--comment--><root2/>";
    char *xml_str = "<root1></root1><root2></root2>";

    assert_os_xml_eq(data, parse_str, xml_str);
}

void test_comments3(void **state) {

    test_struct_t *data  = (test_struct_t *)*state;
    char *parse_str = "<root1/><! comment with ! !><root2/>";
    char *xml_str = "<root1></root1><root2></root2>";

    assert_os_xml_eq(data, parse_str, xml_str);
}

void test_comments4(void **state) {

    test_struct_t *data  = (test_struct_t *)*state;
    char *parse_str = "<root1/><! comment with - --><root2/>";
    char *xml_str = "<root1></root1><root2></root2>";

    assert_os_xml_eq(data, parse_str, xml_str);
}

void test_special_chars(void **state) {

    test_struct_t *data  = (test_struct_t *)*state;
    char *parse_str =   "<var name=\"var1\">value1</var>"
                        "<root1>\\</root1\\></root1>";
    char *xml_str = "<root1>\\</root1\\></root1>";

    assert_os_xml_eq(data, parse_str, xml_str);
}

void test_line_counter(void **state) {

    test_struct_t *data  = (test_struct_t *)*state;
    create_xml_file("<root1/>\n<root2/>\n<root3/>" , data->xml_file_name, 256);

    assert_int_equal(OS_ReadXML(data->xml_file_name, &data->xml), 0);
    assert_int_equal(OS_ApplyVariables(&data->xml), 0);

    data->node = OS_GetElementsbyNode(&data->xml, NULL);
    assert_non_null(data->node);

    assert_int_equal(data->xml.ln[0], 1);
    assert_int_equal(data->xml.ln[1], 2);
    assert_int_equal(data->xml.ln[2], 3);
}

void test_invalid_file(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    assert_int_not_equal(OS_ReadXML("invalid_file.inv", &data->xml), 0);
    assert_string_equal(data->xml.err, "XMLERR: File 'invalid_file.inv' not found.");
    assert_int_equal(data->xml.err_line, 0);
}

void test_unclosed_node1(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    create_xml_file("<root>", data->xml_file_name, 256);

    assert_int_not_equal(OS_ReadXML(data->xml_file_name, &data->xml), 0);
    assert_string_equal(data->xml.err, "XMLERR: End of file and some elements were not closed.");
    assert_int_equal(data->xml.err_line, 1);
}

void test_unclosed_node2(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    char overflow_string[XML_MAXSIZE + 10];
    memset(overflow_string, 'c', XML_MAXSIZE + 9);
    overflow_string[XML_MAXSIZE + 9] = '\0';

    char xml_string[2 * XML_MAXSIZE];
    snprintf(xml_string, 2 * XML_MAXSIZE - 1, "<test>%s", overflow_string);
    create_xml_file(xml_string, data->xml_file_name, 256);

    assert_int_not_equal(OS_ReadXML_Ex(data->xml_file_name, &data->xml, true), 0);
    assert_string_equal(data->xml.err, "XMLERR: End of file and some elements were not closed.");
    assert_int_equal(data->xml.err_line, 1);
}

void test_unclosed_second_node(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    create_xml_file("<root></root2>", data->xml_file_name, 256);

    assert_int_not_equal(OS_ReadXML(data->xml_file_name, &data->xml), 0);
    assert_string_equal(data->xml.err, "XMLERR: Element 'root' not closed.");
    assert_int_equal(data->xml.err_line, 1);
}

void test_unclosed_comment(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    create_xml_file("<!-- comment", data->xml_file_name, 256);
    assert_int_not_equal(OS_ReadXML(data->xml_file_name, &data->xml), 0);
    assert_string_equal(data->xml.err, "XMLERR: Comment not closed.");
    assert_int_equal(data->xml.err_line, 1);
}

void test_node_not_opened(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    create_xml_file("</root>", data->xml_file_name, 256);
    assert_int_not_equal(OS_ReadXML(data->xml_file_name, &data->xml), 0);
    assert_string_equal(data->xml.err, "XMLERR: Element not opened.");
    assert_int_equal(data->xml.err_line, 1);
}

void test_unclosed_attribute(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    create_xml_file("<root attr=\"attribute></root>", data->xml_file_name, 256);
    assert_int_not_equal(OS_ReadXML(data->xml_file_name, &data->xml), 0);
    assert_string_equal(data->xml.err, "XMLERR: Attribute 'attr' not closed.");
    assert_int_equal(data->xml.err_line, 1);
}

void test_unquoted_attribute(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    create_xml_file("<root attr=attribute></root>", data->xml_file_name, 256);
    assert_int_not_equal(OS_ReadXML(data->xml_file_name, &data->xml), 0);
    assert_string_equal(data->xml.err, "XMLERR: Attribute 'attr' not followed by a \" or '.");
    assert_int_equal(data->xml.err_line, 1);
}

void test_infinite_attribute(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    create_xml_file("<root attr", data->xml_file_name, 256);
    assert_int_not_equal(OS_ReadXML(data->xml_file_name, &data->xml), 0);
    assert_string_equal(data->xml.err, "XMLERR: End of file while reading an attribute.");
    assert_int_equal(data->xml.err_line, 1);
}

void test_invalid_variable_name(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    create_xml_file("<var test=\"test\"></var>", data->xml_file_name, 256);
    assert_int_equal(OS_ReadXML(data->xml_file_name, &data->xml), 0);
    assert_int_not_equal(OS_ApplyVariables(&data->xml), 0);
    assert_string_equal(data->xml.err, "XMLERR: Only \"name\" is allowed as an attribute for a variable.");
    assert_int_equal(data->xml.err_line, 1);
}

void test_invalid_variable_double_max_size(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    char overflow_string[XML_VARIABLE_MAXSIZE + 10];
    memset(overflow_string, 'c', XML_VARIABLE_MAXSIZE + 9);
    overflow_string[XML_VARIABLE_MAXSIZE + 9] = '\0';

    char xml_string[2 * XML_VARIABLE_MAXSIZE];
    snprintf(xml_string, 2 * XML_VARIABLE_MAXSIZE - 1, "<var name=\"%s\">test</var><root/>", overflow_string);
    create_xml_file(xml_string, data->xml_file_name, 256);

    assert_int_equal(OS_ReadXML(data->xml_file_name, &data->xml), 0);
    assert_int_not_equal(OS_ApplyVariables(&data->xml), 0);
    assert_string_equal(data->xml.err, "XMLERR: Invalid variable name size.");
    assert_int_equal(data->xml.err_line, 1);
}

void test_invalid_variable_double_max_size2(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    char overflow_string[XML_VARIABLE_MAXSIZE + 10];
    memset(overflow_string, 'c', XML_VARIABLE_MAXSIZE + 9);
    overflow_string[XML_VARIABLE_MAXSIZE + 9] = '\0';

    char xml_string[2 * XML_VARIABLE_MAXSIZE];
    snprintf(xml_string, 2 * XML_VARIABLE_MAXSIZE - 1, "<var name=\"test\">content</var><root>$%s</root>", overflow_string);
    create_xml_file(xml_string, data->xml_file_name, 256);

    assert_int_equal(OS_ReadXML(data->xml_file_name, &data->xml), 0);
    assert_int_not_equal(OS_ApplyVariables(&data->xml), 0);
    assert_string_equal(data->xml.err, "XMLERR: Invalid variable name size: '255'.");
    assert_int_equal(data->xml.err_line, 1);
}

void test_invalid_variable_triple_max_size(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    char overflow_string[XML_VARIABLE_MAXSIZE + 10];
    memset(overflow_string, 'c', XML_VARIABLE_MAXSIZE + 9);
    overflow_string[XML_VARIABLE_MAXSIZE + 9] = '\0';

    char xml_string[3 * XML_VARIABLE_MAXSIZE];
    snprintf(xml_string, 3 * XML_VARIABLE_MAXSIZE - 1, "<var name=\"%s\">test</var><test>$%s</test>", overflow_string, overflow_string);
    create_xml_file(xml_string, data->xml_file_name, 256);

    assert_int_equal(OS_ReadXML(data->xml_file_name, &data->xml), 0);
    assert_int_not_equal(OS_ApplyVariables(&data->xml), 0);
    assert_string_equal(data->xml.err, "XMLERR: Invalid variable name size.");
    assert_int_equal(data->xml.err_line, 1);
}

void test_empty_attribute(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    create_xml_file("<root attr=", data->xml_file_name, 256);

    assert_int_not_equal(OS_ReadXML(data->xml_file_name, &data->xml), 0);
    assert_string_equal(data->xml.err, "XMLERR: Attribute 'attr' not followed by a \" or '.");
    assert_int_equal(data->xml.err_line, 1);
}

void test_invalid_attribute_start(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    create_xml_file("<root attr=  test\"test\"/>", data->xml_file_name, 256);

    assert_int_not_equal(OS_ReadXML(data->xml_file_name, &data->xml), 0);
    assert_string_equal(data->xml.err, "XMLERR: Attribute 'attr' not followed by a \" or '.");
    assert_int_equal(data->xml.err_line, 1);
}

void test_invalid_attribute_closing(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    create_xml_file("<root attr=''", data->xml_file_name, 256);

    assert_int_not_equal(OS_ReadXML(data->xml_file_name, &data->xml), 0);
    assert_string_equal(data->xml.err, "XMLERR: Bad attribute closing for 'attr'=''.");
    assert_int_equal(data->xml.err_line, 1);
}

void test_wrong_variable_name(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    create_xml_file("<var name=\"test\">content</var><root>$var</root>", data->xml_file_name, 256);

    assert_int_equal(OS_ReadXML(data->xml_file_name, &data->xml), 0);
    assert_int_not_equal(OS_ApplyVariables(&data->xml), 0);
    assert_string_equal(data->xml.err, "XMLERR: Unknown variable: 'var'.");
    assert_int_equal(data->xml.err_line, 1);
}

void test_no_value_set_for_variable(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    create_xml_file("<var>content</var><root>$var</root>", data->xml_file_name, 256);

    assert_int_equal(OS_ReadXML(data->xml_file_name, &data->xml), 0);
    assert_int_not_equal(OS_ApplyVariables(&data->xml), 0);
    assert_string_equal(data->xml.err, "XMLERR: No value set for variable.");
    assert_int_equal(data->xml.err_line, 1);
}

void test_unknown_variable(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    char *parse_str = "<root>$var</root>";
    char *xml_str = "<root>$var</root>";

    assert_os_xml_eq(data, parse_str, xml_str);
}

void test_invalid_attribute_closing_no_space(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    create_xml_file("<root attr='test'test/>", data->xml_file_name, 256);

    assert_int_not_equal(OS_ReadXML(data->xml_file_name, &data->xml), 0);
    assert_string_equal(data->xml.err, "XMLERR: Bad attribute closing for 'attr'='test'.");
    assert_int_equal(data->xml.err_line, 1);
}

void test_invalid_attribute_closing_no_second_quote(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    create_xml_file("<root attr='", data->xml_file_name, 256);

    assert_int_not_equal(OS_ReadXML(data->xml_file_name, &data->xml), 0);
    assert_string_equal(data->xml.err, "XMLERR: End of file while reading an attribute.");
    assert_int_equal(data->xml.err_line, 1);
}

void test_duplicated_attribute(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    create_xml_file("<root attr='test' attr2='test' attr='test123'></root>", data->xml_file_name, 256);

    assert_int_not_equal(OS_ReadXML(data->xml_file_name, &data->xml), 0);
    assert_string_equal(data->xml.err, "XMLERR: Attribute 'attr' already defined.");
    assert_int_equal(data->xml.err_line, 1);
}

void test_no_attribute_value(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    create_xml_file("<root attr></root>", data->xml_file_name, 256);

    assert_int_not_equal(OS_ReadXML(data->xml_file_name, &data->xml), 0);
    assert_string_equal(data->xml.err, "XMLERR: Attribute 'attr' has no value.");
    assert_int_equal(data->xml.err_line, 1);
}

void test_no_first_attribute_value(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    create_xml_file("<root attr attr2='test'></root>", data->xml_file_name, 256);

    assert_int_not_equal(OS_ReadXML(data->xml_file_name, &data->xml), 0);
    assert_string_equal(data->xml.err, "XMLERR: Attribute 'attr' has no value.");
    assert_int_equal(data->xml.err_line, 1);
}

void test_os_root_elements_exists(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    create_xml_file("<root></root><root1/><root/>", data->xml_file_name, 256);

    assert_int_equal(OS_ReadXML(data->xml_file_name, &data->xml), 0);
    assert_int_equal(OS_ApplyVariables(&data->xml), 0);
    assert_int_equal(OS_RootElementExist(&data->xml, "root"), 2);
    assert_int_equal(OS_RootElementExist(&data->xml, "root1"), 1);
    assert_int_equal(OS_RootElementExist(&data->xml, "root2"), 0);
    char *element = NULL;
    assert_int_equal(OS_RootElementExist(&data->xml, element), 0);
}

void test_os_get_one_content_for_element(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    create_xml_file("<root><child>test</child><child>test2</child><child2>test</child2></root>", data->xml_file_name, 256);

    assert_int_equal(OS_ReadXML(data->xml_file_name, &data->xml), 0);
    assert_int_equal(OS_ApplyVariables(&data->xml), 0);

    const char *xml_path1[] = { "root", "child", NULL };
    const char *xml_path2[] = { "root", "child2", NULL };
    const char *xml_path3[] = { "root", "child3", NULL };

    data->content1 = OS_GetOneContentforElement(&data->xml, xml_path1);
    assert_string_equal(data->content1, "test");

    data->content2 = OS_GetOneContentforElement(&data->xml, xml_path2);
    assert_string_equal(data->content2, "test");

    assert_null(OS_GetOneContentforElement(&data->xml, xml_path3));
}

void test_os_write_xml_success1(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    const char *xml_path[] = { "root", "child", NULL };
    const char *xml_str_old = "<root1></root1>""<root2></root2>""<root3/>";
    const char *xml_str_new = "<root1></root1>""<root2></root2>""<root3></root3>";

    assert_ox_xml_write_eq(data, xml_str_old, xml_str_new, xml_path, "test", "test_new");
}

void test_os_write_xml_success2(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    const char *xml_path[] = { "root", "child", NULL };
    const char *xml_str_old = "<root><child>test</child></root>";
    const char *xml_str_new = "<root><child>test</child></root>";

    assert_ox_xml_write_eq(data, xml_str_old, xml_str_new, xml_path, "test", "test");
}

void test_os_write_xml_success3(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    const char *xml_path[] = { "root", "child", NULL };
    const char *xml_str_old = "<root><child></child></root>";
    const char *xml_str_new = "<root><child>test</child></root>";

    assert_ox_xml_write_eq(data, xml_str_old, xml_str_new, xml_path, "test", "test");
}

void test_os_write_xml_success4(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    const char *xml_path[] = { "root", "child", NULL };
    const char *xml_str_old = "<root2><child></child></root2>";
    const char *xml_str_new = "<root2><child></child></root2><root>\n <child>test</child></root>";

    assert_ox_xml_write_eq(data, xml_str_old, xml_str_new, xml_path, NULL, "test");
}

void test_os_write_xml_success5(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    const char *xml_path[] = { "root", "child", NULL };
    const char *xml_str_old = "<!--Comment--><root><child>test</child></root>";
    const char *xml_str_new = "<root><child>test</child></root>";

    assert_ox_xml_write_eq(data, xml_str_old, xml_str_new, xml_path, "test", "test");
}

void test_os_write_xml_failures(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    create_xml_file("<root><child>test</child></root>", data->xml_file_name, 256);

    create_xml_file("", data->xml_out_file_name, 256);

    const char *xml_path[] = { "root", "child", NULL };
    assert_int_equal(OS_WriteXML("invalid", data->xml_out_file_name, xml_path, "test", "test_new"), XMLW_NOIN);
    assert_int_equal(OS_WriteXML(data->xml_file_name, "??invalid<<!!\"\"//\\\\", xml_path, "test", "test_new"), XMLW_NOOUT);

    create_xml_file("<!--Invalid comment--", data->xml_file_name, 256);
    assert_int_equal(OS_WriteXML(data->xml_file_name, data->xml_out_file_name, xml_path, "test", "test_new"), XMLW_ERROR);
}

void test_os_get_attribute_content(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    create_xml_file("<root attr=\"value\" attr2=\"value1\"></root>", data->xml_file_name, 256);

    assert_int_equal(OS_ReadXML(data->xml_file_name, &data->xml), 0);
    assert_int_equal(OS_ApplyVariables(&data->xml), 0);

    const char *xml_path1[] = { "root", NULL };
    const char *xml_path2[] = { NULL };

    data->content1 = OS_GetAttributeContent(&data->xml, xml_path1, "attr");
    assert_string_equal(data->content1, "value");

    data->content2 = OS_GetAttributeContent(&data->xml, xml_path1, "attr2");
    assert_string_equal(data->content2, "value1");

    data->content3 = OS_GetAttributeContent(&data->xml, xml_path1, "attr3");
    assert_string_equal(data->content3, "");

    data->content4 = OS_GetAttributeContent(&data->xml, xml_path1, NULL);
    assert_string_equal(data->content4, "");

    assert_null(OS_GetAttributeContent(&data->xml, xml_path2, NULL));
}

void test_os_get_contents(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    create_xml_file("<root>value</root><root>value2</root><root2>value</root2>", data->xml_file_name, 256);

    assert_int_equal(OS_ReadXML(data->xml_file_name, &data->xml), 0);
    assert_int_equal(OS_ApplyVariables(&data->xml), 0);
    const char *xml_path1[] = { "root", NULL };
    const char *xml_path2[] = { "root2", NULL };

    assert_non_null(data->content5 = OS_GetContents(&data->xml, xml_path1));
    assert_string_equal(data->content5[0], "value");
    assert_string_equal(data->content5[1], "value2");
    assert_null(data->content5[2]);

    assert_non_null(data->content6 = OS_GetContents(&data->xml, xml_path2));
    assert_string_equal(data->content6[0], "value");
    assert_null(data->content6[1]);

    assert_null(OS_GetContents(&data->xml, NULL));
}

void test_os_get_element_content1(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    create_xml_file("<root>value</root>", data->xml_file_name, 256);

    assert_int_equal(OS_ReadXML(data->xml_file_name, &data->xml), 0);
    assert_int_equal(OS_ApplyVariables(&data->xml), 0);
    const char *xml_path[] = { "root", NULL };

    data->content5 = OS_GetElementContent(&data->xml, xml_path);
    assert_non_null(data->content5);
    assert_string_equal(data->content5[0], "value");
    assert_null(data->content5[1]);
}

void test_os_get_element_content_maximum_depth(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    create_xml_file("<root><root1><root2><root3><root4><root5><root6><root7><root8><root9><root10><root11><root12><root13><root14><root15><root16><root17>value</root17></root16></root15></root14></root13></root12></root11></root10></root9></root8></root7></root6></root5></root4></root3></root2></root1></root>", data->xml_file_name, 256);

    assert_int_equal(OS_ReadXML(data->xml_file_name, &data->xml), 0);
    assert_int_equal(OS_ApplyVariables(&data->xml), 0);
    const char *xml_path[] = { "root", "root1", "root2", "root3", "root4", "root5", "root6", "root7", "root8", "root9", "root10",
                                "root11", "root12", "root13", "root14", "root15", "root16", "root17", NULL };

    data->content5 = OS_GetElementContent(&data->xml, xml_path);
    assert_null(data->content5);
}

void test_get_element_content(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    create_xml_file("<root>value</root>", data->xml_file_name, 256);

    assert_int_equal(OS_ReadXML(data->xml_file_name, &data->xml), 0);
    assert_int_equal(OS_ApplyVariables(&data->xml), 0);
    const char *xml_path[] = { "root", NULL };

    data->xml.fol = 1;
    data->content5 = OS_GetContents(&data->xml, xml_path);
    assert_null(data->content5);
}

void test_os_get_elements(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    create_xml_file("<root><child1/><child2/></root>", data->xml_file_name, 256);

    assert_int_equal(OS_ReadXML(data->xml_file_name, &data->xml), 0);
    assert_int_equal(OS_ApplyVariables(&data->xml), 0);
    const char *xml_path[] = { "root", NULL };

    data->content5 = OS_GetElements(&data->xml, xml_path);
    assert_non_null(data->content5);
    assert_string_equal(data->content5[0], "child1");
    assert_string_equal(data->content5[1], "child2");
    assert_null(data->content5[2]);

    data->content6 = OS_GetElements(&data->xml, NULL);
    assert_non_null(data->content6);
    assert_string_equal(data->content6[0], "root");
    assert_null(data->content6[1]);

    const char *xml_path2[] = { NULL };
    assert_null(OS_GetElements(&data->xml,  xml_path2));
}

void test_os_get_elements2(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    create_xml_file("<root><child1/></root><root1><child2/></root1>", data->xml_file_name, 256);

    assert_int_equal(OS_ReadXML(data->xml_file_name, &data->xml), 0);
    assert_int_equal(OS_ApplyVariables(&data->xml), 0);
    const char *xml_path[] = { "root", "root1", NULL };

    data->content5 = OS_GetElements(&data->xml, xml_path);
    assert_null(data->content5);
}

void test_os_get_elements3(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    create_xml_file("<root><root1><root2><root3><root4><root5><root6><root7><root8><root9><root10><root11><root12><root13><root14><root15><root16><root17>value</root17></root16></root15></root14></root13></root12></root11></root10></root9></root8></root7></root6></root5></root4></root3></root2></root1></root>", data->xml_file_name, 256);

    assert_int_equal(OS_ReadXML(data->xml_file_name, &data->xml), 0);
    assert_int_equal(OS_ApplyVariables(&data->xml), 0);
    const char *xml_path[] = { "root", "root1", "root2", "root3", "root4", "root5", "root6", "root7", "root8", "root9", "root10",
                                "root11", "root12", "root13", "root14", "root15", "root16", "root17", NULL };

    data->content5 = OS_GetElements(&data->xml, xml_path);
    assert_null(data->content5);
}

void test_os_get_attributes(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    create_xml_file("<root attr1=\"1\" attr2=\"2\"></root>", data->xml_file_name, 256);

    assert_int_equal(OS_ReadXML(data->xml_file_name, &data->xml), 0);
    assert_int_equal(OS_ApplyVariables(&data->xml), 0);
    const char *xml_path[] = { "root", NULL };

    assert_non_null(data->content5 = OS_GetAttributes(&data->xml, xml_path));
    assert_string_equal(data->content5[0], "attr1");
    assert_string_equal(data->content5[1], "attr2");
    assert_null(data->content5[2]);
}

void test_node_name_overflow1(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    char overflow_string[XML_MAXSIZE + 10];
    memset(overflow_string, 'c', XML_MAXSIZE + 9);
    overflow_string[XML_MAXSIZE + 9] = '\0';

    char xml_string[2 * XML_MAXSIZE];
    snprintf(xml_string, 2 * XML_MAXSIZE - 1, "<%s/>", overflow_string);
    create_xml_file(xml_string, data->xml_file_name, 256);

    assert_int_not_equal(OS_ReadXML(data->xml_file_name, &data->xml), 0);
    assert_string_equal(data->xml.err, "XMLERR: String overflow.");
    assert_int_equal(data->xml.err_line, 1);
}

void test_node_name_overflow2(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    char overflow_string[XML_MAXSIZE + 10];
    memset(overflow_string, 'c', XML_MAXSIZE + 9);
    overflow_string[XML_MAXSIZE + 9] = '\0';

    char xml_string[2 * XML_MAXSIZE];
    snprintf(xml_string, 2 * XML_MAXSIZE - 1, "<%s/>", overflow_string);
    create_xml_file(xml_string, data->xml_file_name, 256);

    assert_int_not_equal(OS_ReadXML_Ex(data->xml_file_name, &data->xml, true), 0);
    assert_string_equal(data->xml.err, "XMLERR: String overflow.");
    assert_int_equal(data->xml.err_line, 1);
}

void test_node_value_overflow(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    char overflow_string[XML_MAXSIZE + 10];
    memset(overflow_string, 'c', XML_MAXSIZE + 9);
    overflow_string[XML_MAXSIZE + 9] = '\0';

    char xml_string[2 * XML_MAXSIZE];
    snprintf(xml_string, 2 * XML_MAXSIZE - 1, "<test>%s</test>", overflow_string);
    create_xml_file(xml_string, data->xml_file_name, 256);

    assert_int_not_equal(OS_ReadXML(data->xml_file_name, &data->xml), 0);
    assert_string_equal(data->xml.err, "XMLERR: String overflow.");
    assert_int_equal(data->xml.err_line, 1);
}

void test_node_value_truncate_overflow(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    char overflow_string[XML_MAXSIZE + 10];
    memset(overflow_string, 'c', XML_MAXSIZE + 9);
    overflow_string[XML_MAXSIZE + 9] = '\0';

    char xml_string[2 * XML_MAXSIZE];
    snprintf(xml_string, 2 * XML_MAXSIZE - 1, "<test>%s</test>", overflow_string);
    create_xml_file(xml_string, data->xml_file_name, 256);

    const char *xml_path[] = { "test", NULL };

    assert_int_equal(OS_ReadXML_Ex(data->xml_file_name, &data->xml, true), 0);
    assert_non_null(data->content5 = OS_GetContents(&data->xml, xml_path));
    assert_string_equal(data->content5[0], overflow_string+9);
}

void test_node_attribute_name_overflow(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    char overflow_string[XML_MAXSIZE + 10];
    memset(overflow_string, 'c', XML_MAXSIZE + 9);
    overflow_string[XML_MAXSIZE + 9] = '\0';

    char xml_string[2 * XML_MAXSIZE];
    snprintf(xml_string, 2 * XML_MAXSIZE - 1, "<test %s=\"test\">test</test>", overflow_string);
    create_xml_file(xml_string, data->xml_file_name, 256);

    assert_int_not_equal(OS_ReadXML(data->xml_file_name, &data->xml), 0);
    assert_string_equal(data->xml.err, "XMLERR: Overflow attempt at attribute 'cccccccccccccccccccc'.");
    assert_int_equal(data->xml.err_line, 1);
}

void test_node_attribute_value_overflow(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    char overflow_string[XML_MAXSIZE + 10];
    memset(overflow_string, 'c', XML_MAXSIZE + 9);
    overflow_string[XML_MAXSIZE + 9] = '\0';

    char xml_string[2 * XML_MAXSIZE];
    snprintf(xml_string, 2 * XML_MAXSIZE - 1, "<test test=\"%s\">test</test>", overflow_string);
    create_xml_file(xml_string, data->xml_file_name, 256);

    assert_int_not_equal(OS_ReadXML(data->xml_file_name, &data->xml), 0);
    assert_string_equal(data->xml.err, "XMLERR: Overflow attempt at attribute 'test'.");
    assert_int_equal(data->xml.err_line, 1);
}

void test_os_readxml_non_empty_tag(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    create_xml_file("<element-name>test</element-name>", data->xml_file_name, 256);

    assert_int_equal(OS_ReadXML(data->xml_file_name, &data->xml), 0);
    assert_int_equal(OS_RootElementExist(&data->xml, "element-name"), 1);
}

void test_os_readxml_non_empty_tag_space_at_start(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    create_xml_file("  <element-name>test</element-name>", data->xml_file_name, 256);

    assert_int_equal(OS_ReadXML(data->xml_file_name, &data->xml), 0);
    assert_int_equal(OS_RootElementExist(&data->xml, "element-name"), 1);
}

void test_os_readxml_non_empty_tag_newline_at_start(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    create_xml_file("\n<element-name>test</element-name>", data->xml_file_name, 256);

    assert_int_equal(OS_ReadXML(data->xml_file_name, &data->xml), 0);
    assert_int_equal(OS_RootElementExist(&data->xml, "element-name"), 1);
}

void test_os_readxml_non_empty_tag_tab_at_start(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    create_xml_file("\t<element-name>test</element-name>", data->xml_file_name, 256);

    assert_int_equal(OS_ReadXML(data->xml_file_name, &data->xml), 0);
    assert_int_equal(OS_RootElementExist(&data->xml, "element-name"), 1);
}

void test_os_readxml_non_empty_tag_different_spaces_at_start(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    create_xml_file("\t\n <element-name>test</element-name>", data->xml_file_name, 256);

    assert_int_equal(OS_ReadXML(data->xml_file_name, &data->xml), 0);
    assert_int_equal(OS_RootElementExist(&data->xml, "element-name"), 1);
}

void test_os_readxml_non_empty_tag_inside_quotes(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    create_xml_file("\"<element-name>\"test\"</element-name>\"", data->xml_file_name, 256);

    assert_int_not_equal(OS_ReadXML(data->xml_file_name, &data->xml), 0);
    assert_string_equal(data->xml.err, "XMLERR: Malformed XML does not start with '<'");
    assert_int_equal(data->xml.err_line, 1);
}

void test_os_readxml_xml_inside_non_json(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    create_xml_file("{{\"field\":\"value\"},{<element-name>test</element-name>}}", data->xml_file_name, 256);

    assert_int_not_equal(OS_ReadXML(data->xml_file_name, &data->xml), 0);
    assert_string_equal(data->xml.err, "XMLERR: Malformed XML does not start with '<'");
    assert_int_equal(data->xml.err_line, 1);
}

void test_os_readxml_random_string_with_valid_xml(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    create_xml_file("\"field\"asidpoaisdpoa $$ :\"value\"},{<element-name>test</element-name>}}", data->xml_file_name, 256);

    assert_int_not_equal(OS_ReadXML(data->xml_file_name, &data->xml), 0);
    assert_string_equal(data->xml.err, "XMLERR: Malformed XML does not start with '<'");
    assert_int_equal(data->xml.err_line, 1);
}

void test_os_readxml_empty_tag(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    create_xml_file("<   >test</   >", data->xml_file_name, 256);

    assert_int_not_equal(OS_ReadXML(data->xml_file_name, &data->xml), 0);
    assert_string_equal(data->xml.err, "XMLERR: Element '' not closed.");
    assert_int_equal(data->xml.err_line, 1);
}

void test_node_attribute_value_truncate_overflow(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    char overflow_string[XML_MAXSIZE + 10];
    memset(overflow_string, 'c', XML_MAXSIZE + 9);
    overflow_string[XML_MAXSIZE + 9] = '\0';

    char xml_string[2 * XML_MAXSIZE];
    snprintf(xml_string, 2 * XML_MAXSIZE - 1, "<test attr=\"%s\"></test>", overflow_string);
    create_xml_file(xml_string, data->xml_file_name, 256);
    const char *xml_path[] = { "test", NULL };

    assert_int_equal(OS_ReadXML_Ex(data->xml_file_name, &data->xml, true), 0);
    assert_non_null(data->content1 = OS_GetAttributeContent(&data->xml, xml_path, "attr"));
}

void w_get_attr_val_by_name_null_attr(void ** state) {

    xml_node node = {0};
    const char * retval;

    retval = w_get_attr_val_by_name(&node, "test_attr_name");

    assert_null(retval);
}

void w_get_attr_val_by_name_not_found(void ** state) {

    xml_node node = {0};
    char * attributes[] = {"attr_name_1", "attr_name_2", NULL};
    char * values[] = {"attr_val_1", "attr_val_2", NULL};

    node.attributes = attributes;
    node.values = values;
    const char * retval;

    retval = w_get_attr_val_by_name(&node, "test_attr_name");

    assert_null(retval);
}

void w_get_attr_val_by_name_found(void ** state) {

    xml_node node = {0};
    char * attributes[] = {"attr_name_1", "test_attr_name", "attr_name_3", NULL};
    char * values[] = {"attr_val_1", "test_attr_value", "attr_val_3", NULL};

    node.attributes = attributes;
    node.values = values;
    const char * retval;

    retval = w_get_attr_val_by_name(&node, "test_attr_name");

    assert_non_null(retval);
    assert_string_equal(retval, "test_attr_value");
}

int main(void) {
    const struct CMUnitTest tests[] = {

        // Test w_get_attr_val_by_name
        cmocka_unit_test(w_get_attr_val_by_name_null_attr),
        cmocka_unit_test(w_get_attr_val_by_name_not_found),
        cmocka_unit_test(w_get_attr_val_by_name_found),

        // Simple XML node test
        cmocka_unit_test_setup_teardown(test_simple_nodes1, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_simple_nodes2, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_simple_nodes3, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_simple_nodes4, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_simple_nodes5, test_setup, test_teardown),

        // Multiple XML nodes test
        cmocka_unit_test_setup_teardown(test_multiple_nodes, test_setup, test_teardown),

        // Childen on XML nodes test
        cmocka_unit_test_setup_teardown(test_children, test_setup, test_teardown),

        // Childen on XML nodes test
        cmocka_unit_test_setup_teardown(test_multiple_content, test_setup, test_teardown),

        // Attributes inside XML test
        cmocka_unit_test_setup_teardown(test_attributes1, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_attributes2, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_attributes3, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_attributes4, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_attributes5, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_attributes6, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_attributes7, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_attributes8, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_attributes9, test_setup, test_teardown),

        // Variables inside XML test
        cmocka_unit_test_setup_teardown(test_variables, test_setup, test_teardown),

        // Comments inside XML test
        cmocka_unit_test_setup_teardown(test_comments1, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_comments2, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_comments3, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_comments4, test_setup, test_teardown),

        // Special chars inside XML test
        cmocka_unit_test_setup_teardown(test_special_chars, test_setup, test_teardown),

        // Line counter inside XML test
        cmocka_unit_test_setup_teardown(test_line_counter, test_setup, test_teardown),

        // Invalid XML test
        cmocka_unit_test_setup_teardown(test_invalid_file, test_setup, test_teardown),

        // Unclosed node XML test
        cmocka_unit_test_setup_teardown(test_unclosed_node1, test_setup, test_teardown),

        // Unclosed node XML test when truncate flag is set
        cmocka_unit_test_setup_teardown(test_unclosed_node2, test_setup, test_teardown),

        // Unclosed second node XML test
        cmocka_unit_test_setup_teardown(test_unclosed_second_node, test_setup, test_teardown),

        // Unclosed comment inside XML test
        cmocka_unit_test_setup_teardown(test_unclosed_comment, test_setup, test_teardown),

        // Node not opened inside XML test
        cmocka_unit_test_setup_teardown(test_node_not_opened, test_setup, test_teardown),

        // Unclosed attribute inside XML test
        cmocka_unit_test_setup_teardown(test_unclosed_attribute, test_setup, test_teardown),

        // Unquoted attribute inside XML test
        cmocka_unit_test_setup_teardown(test_unquoted_attribute, test_setup, test_teardown),

        // Infinite attribute inside XML test
        cmocka_unit_test_setup_teardown(test_infinite_attribute, test_setup, test_teardown),

        // Invalid variable name inside XML test
        cmocka_unit_test_setup_teardown(test_invalid_variable_name, test_setup, test_teardown),

        // Invalid variable name (2*MAX_SIZE) inside XML test
        cmocka_unit_test_setup_teardown(test_invalid_variable_double_max_size, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_invalid_variable_double_max_size2, test_setup, test_teardown),

        // Invalid variable name (3*MAX_SIZE) inside XML test
        cmocka_unit_test_setup_teardown(test_invalid_variable_triple_max_size, test_setup, test_teardown),

        // Empty attribute inside XML test
        cmocka_unit_test_setup_teardown(test_empty_attribute, test_setup, test_teardown),

        // Empty attribute start inside XML test
        cmocka_unit_test_setup_teardown(test_invalid_attribute_start, test_setup, test_teardown),

        // Invalid attribute closing inside XML test
        cmocka_unit_test_setup_teardown(test_invalid_attribute_closing, test_setup, test_teardown),

        // Wrong variable name inside XML test
        cmocka_unit_test_setup_teardown(test_wrong_variable_name, test_setup, test_teardown),

        // Wrong no value set for variable inside XML test
        cmocka_unit_test_setup_teardown(test_no_value_set_for_variable, test_setup, test_teardown),

        // Unknown variable inside XML test
        cmocka_unit_test_setup_teardown(test_unknown_variable, test_setup, test_teardown),

        // Invalid attribute closing (no space) inside XML test
        cmocka_unit_test_setup_teardown(test_invalid_attribute_closing_no_space, test_setup, test_teardown),

        // Invalid attribute closing (no second quote) inside XML test
        cmocka_unit_test_setup_teardown(test_invalid_attribute_closing_no_second_quote, test_setup, test_teardown),

        // Duplicated attribute inside XML test
        cmocka_unit_test_setup_teardown(test_duplicated_attribute, test_setup, test_teardown),

        // No attribute value inside XML test
        cmocka_unit_test_setup_teardown(test_no_attribute_value, test_setup, test_teardown),

        // No first attribute value inside XML test
        cmocka_unit_test_setup_teardown(test_no_first_attribute_value, test_setup, test_teardown),

        // OS_RootElementExist test
        cmocka_unit_test_setup_teardown(test_os_root_elements_exists, test_setup, test_teardown),

        // OS_GetOneContentforElement test
        cmocka_unit_test_setup_teardown(test_os_get_one_content_for_element, test_setup, test_teardown),

        // OS_WriteXML test
        cmocka_unit_test_setup_teardown(test_os_write_xml_success1, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_os_write_xml_success2, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_os_write_xml_success3, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_os_write_xml_success4, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_os_write_xml_success5, test_setup, test_teardown),

        // OS_WriteXML failures test
        cmocka_unit_test_setup_teardown(test_os_write_xml_failures, test_setup, test_teardown),

        // OS_GetAttributeContent test
        cmocka_unit_test_setup_teardown(test_os_get_attribute_content, test_setup, test_teardown),

        // OS_GetContents test
        cmocka_unit_test_setup_teardown(test_os_get_contents, test_setup, test_teardown),

        // OS_GetElementContent test
        cmocka_unit_test_setup_teardown(test_os_get_element_content1, test_setup, test_teardown),

        // OS_GetElementContent test maximum depth
        cmocka_unit_test_setup_teardown(test_os_get_element_content_maximum_depth, test_setup, test_teardown),

        // _GetElementContent test
        cmocka_unit_test_setup_teardown(test_get_element_content, test_setup, test_teardown),

        // OS_GetElements test
        cmocka_unit_test_setup_teardown(test_os_get_elements, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_os_get_elements2, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_os_get_elements3, test_setup, test_teardown),

        // OS_GetAttributes test
        cmocka_unit_test_setup_teardown(test_os_get_attributes, test_setup, test_teardown),

        // Node name inside XML overflow test
        cmocka_unit_test_setup_teardown(test_node_name_overflow1, test_setup, test_teardown),

        // Node name inside XML overflow test. Node name is never truncated
        cmocka_unit_test_setup_teardown(test_node_name_overflow2, test_setup, test_teardown),

        // Node value inside XML overflow test
        cmocka_unit_test_setup_teardown(test_node_value_overflow, test_setup, test_teardown),

        // Node value inside XML truncate overflow test
        cmocka_unit_test_setup_teardown(test_node_value_truncate_overflow, test_setup, test_teardown),

        // Node attribute name inside XML overflow test
        cmocka_unit_test_setup_teardown(test_node_attribute_name_overflow, test_setup, test_teardown),

        // Node attribute value inside XML overflow test
        cmocka_unit_test_setup_teardown(test_node_attribute_value_overflow, test_setup, test_teardown),

        // Truncate node attribute value inside XML overflow test
        cmocka_unit_test_setup_teardown(test_node_attribute_value_truncate_overflow, test_setup, test_teardown),

        // OS_ReadXML tests
        cmocka_unit_test_setup_teardown(test_os_readxml_non_empty_tag, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_os_readxml_non_empty_tag_space_at_start, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_os_readxml_non_empty_tag_newline_at_start, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_os_readxml_non_empty_tag_tab_at_start, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_os_readxml_non_empty_tag_different_spaces_at_start, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_os_readxml_non_empty_tag_inside_quotes, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_os_readxml_xml_inside_non_json, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_os_readxml_random_string_with_valid_xml, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_os_readxml_non_empty_tag, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_os_readxml_empty_tag, test_setup, test_teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
