#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include "../os_xml/os_xml.h"
#include "../os_xml/os_xml_internal.h"
#include "tap.h"

static void create_xml_file(const char *str, char file_name[], size_t length) {
    strncpy(file_name, "/tmp/tmp_file-XXXXXX", length);
    int fd = mkstemp(file_name);

    write(fd, str, strlen(str));
    close(fd);
}

static int nodecat(XML_NODE node, OS_XML *xml, char *buffer) {
    int i = 0;
    /* write node */
    while (node[i]) {
        strncat(buffer, "<", 1);
        w_assert_ptr_ne(node[i]->element, NULL);
        strncat(buffer, node[i]->element, strlen(node[i]->element));
        /* write attributes */
        if (node[i]->attributes) {
            w_assert_ptr_ne(node[i]->values, NULL);
            int j = 0;
            while (node[i]->attributes[j]) {
                strncat(buffer, " ", 1);
                w_assert_ptr_ne(node[i]->values[j], NULL);
                strncat(buffer, node[i]->attributes[j], strlen(node[i]->attributes[j]));
                strncat(buffer, "=", 1);
                strncat(buffer, "\"", 1);
                strncat(buffer, node[i]->values[j], strlen(node[i]->values[j]));
                strncat(buffer, "\"", 1);
                j++;
            }
            w_assert_ptr_eq(node[i]->values[j], NULL);
        } else {
            w_assert_ptr_eq(node[i]->values, NULL);
        }
        strncat(buffer, ">", 1);
        w_assert_ptr_ne(node[i]->content, NULL);
        strncat(buffer, node[i]->content, strlen(node[i]->content));

        /* write children */
        XML_NODE child = OS_GetElementsbyNode(xml, node[i]);
        if (child != NULL) {
            nodecat(child, xml, buffer);
            OS_ClearNode(child);
        }

        /* close node */
        strncat(buffer, "</", 2);
        strncat(buffer, node[i]->element, strlen(node[i]->element));
        strncat(buffer, ">", 1);
        i++;
    }
    return 1;
}

static int assert_os_xml_eq_str(OS_XML *xml, const char *xml_str) {
    XML_NODE node = OS_GetElementsbyNode(xml, NULL);
    if (node == NULL) {
        w_assert_str_eq(xml_str, "");
        return 1;
    }

    char *buffer = (char *) malloc(6144 * sizeof(char));
    buffer[0] = '\0';
    nodecat(node, xml, buffer);
    OS_ClearNode(node);

    w_assert_str_eq(buffer, xml_str);

    free(buffer);
    return 1;
}

int assert_os_xml_eq(char *parse_str, char *xml_str){
    char _w_xml_file_name[256];
    create_xml_file(parse_str, _w_xml_file_name, 256);
    OS_XML _w_xml;
    w_assert_int_eq(OS_ReadXML(_w_xml_file_name, &_w_xml), 0);
    w_assert_int_eq(OS_ApplyVariables(&_w_xml), 0);
    if(!assert_os_xml_eq_str(&_w_xml, xml_str)){
        OS_ClearXML(&_w_xml);
        unlink(_w_xml_file_name);
        return 0;
    }
    OS_ClearXML(&_w_xml);
    unlink(_w_xml_file_name);
    return 1;
}

int assert_ox_xml_write_eq(const char *xml_str_old, const char *xml_str_new, const char **xml_path, const char *oldval, const char *newval){
    char xml_in_file_name[256];
    create_xml_file(xml_str_old, xml_in_file_name, 256);
    char xml_out_file_name[256];
    create_xml_file("", xml_out_file_name, 256);

    w_assert_int_eq(OS_WriteXML(xml_in_file_name, xml_out_file_name, xml_path, oldval, newval), 0);

    OS_XML xml;
    w_assert_int_eq(OS_ReadXML(xml_out_file_name, &xml), 0);
    w_assert_int_eq(OS_ApplyVariables(&xml), 0);
    if(!assert_os_xml_eq_str(&xml, xml_str_new)){
        OS_ClearXML(&xml);
        unlink(xml_in_file_name);
        unlink(xml_out_file_name);
        return 0;
    }

    OS_ClearXML(&xml);
    unlink(xml_in_file_name);
    unlink(xml_out_file_name);
    return 1;
}

int test_simple_nodes() {
    if(!assert_os_xml_eq("", "")) return 0;
    if(!assert_os_xml_eq("<root></root>", "<root></root>")) return 0;
    if(!assert_os_xml_eq("<root/>", "<root></root>")) return 0;
    if(!assert_os_xml_eq("<root />", "<root></root>")) return 0;
    return 1;
}

int test_multiple_nodes() {
    return assert_os_xml_eq(
        "<root1></root1>"
        "<root2></root2>"
        "<root3/>",
        "<root1></root1>"
        "<root2></root2>"
        "<root3></root3>");
}

int test_children() {
    return assert_os_xml_eq(
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

int test_multiple_content() {
    return (assert_os_xml_eq(
        "<root>"
        "value1"
        "<child/>"
        "</root>",
        "<root><child></child></root>") 
        &&
    assert_os_xml_eq(
        "<root>"
        "value1"
        "<child/>"
        "value2"
        "</root>",
        "<root>value2<child></child></root>"));
}

int test_attributes() {
    if(!assert_os_xml_eq(
        "<root attr1=\"test\" attr2=\"1\"></root>",
        "<root attr1=\"test\" attr2=\"1\"></root>")){
        return 0;
    }

    if(!assert_os_xml_eq(
        "<root attr1=\"test\"\nattr2=\"test\"\tattr3=\"test\"></root>",
        "<root attr1=\"test\" attr2=\"test\" attr3=\"test\"></root>")){
        return 0;
    }

    if(!assert_os_xml_eq(
        "<root attr1=\"test/test\"></root>",
        "<root attr1=\"test/test\"></root>")){
        return 0;
    }

    if(!assert_os_xml_eq(
        "<root attr1=\"test1\"></root><root attr1=\"test2\"></root>",
        "<root attr1=\"test1\"></root><root attr1=\"test2\"></root>")){
        return 0;
    }

    if(!assert_os_xml_eq(
        "<root attr1=\"test\"\n\t  \t\n  \n\t  \nattr2=\"test\"></root>",
        "<root attr1=\"test\" attr2=\"test\"></root>")){
        return 0;
    }

    if(!assert_os_xml_eq(
        "<root\n\t  \t\n  \n\t  \nattr1=\"test\"></root>",
        "<root attr1=\"test\"></root>")){
        return 0;
    }

    if(!assert_os_xml_eq(
        "<root attr1=\n\t  \t\n  \n\t  \n\"test\"></root>",
        "<root attr1=\"test\"></root>")){
        return 0;
    }

    if(!assert_os_xml_eq(
        "<root attr=\"test\" />",
        "<root attr=\"test\"></root>")){
        return 0;
    }

    if(!assert_os_xml_eq(
        "<root attr=\"test\"/>",
        "<root attr=\"test\"></root>")){
        return 0;
    }
    return 1;
}

int test_variables() {
        return assert_os_xml_eq(
        "<var name=\"var1\">value1</var>"
        "<var name=\"var2\">value2</var>"
        "<root attr1=\"$var1\" attr2=\"1\">$var2</root>"
        "<root attr1=\"blah$var1\" attr2=\"1\">blah$var2</root>"
        "<root attr1=\"blah$var1$var2 blah\" attr2=\"1\">blah$var2$var1 blah</root>",
        "<root attr1=\"value1\" attr2=\"1\">value2</root>"
        "<root attr1=\"blahvalue1\" attr2=\"1\">blahvalue2</root>"
        "<root attr1=\"blahvalue1value2 blah\" attr2=\"1\">blahvalue2value1 blah</root>");
}

int test_comments() {
    if(!assert_os_xml_eq(
        "<root1/><!comment!><root2/>",
        "<root1></root1><root2></root2>")){
        return 0;
    }
    if(!assert_os_xml_eq(
        "<root1/><!--comment--><root2/>",
        "<root1></root1><root2></root2>")){
        return 0;
    }

    if(!assert_os_xml_eq(
        "<root1/><! comment with ! !><root2/>",
        "<root1></root1><root2></root2>")){
        return 0;
    }

    if(!assert_os_xml_eq(
        "<root1/><! comment with - --><root2/>",
        "<root1></root1><root2></root2>")){
        return 0;
    }
    return 1;
}

int test_special_chars() {
    return assert_os_xml_eq(
        "<var name=\"var1\">value1</var>"
        "<root1>\\</root1\\></root1>",
        "<root1>\\</root1\\></root1>");
}

int test_line_counter() {
    char xml_file_name[256];
    create_xml_file("<root1/>\n<root2/>\n<root3/>" , xml_file_name, 256);
    OS_XML xml;
    XML_NODE node;
    w_assert_int_eq(OS_ReadXML(xml_file_name, &xml), 0);
    w_assert_int_eq(OS_ApplyVariables(&xml), 0);
    w_assert_ptr_ne(node = OS_GetElementsbyNode(&xml, NULL), NULL);
    w_assert_int_eq(xml.ln[0], 1);
    w_assert_int_eq(xml.ln[1], 2);
    w_assert_int_eq(xml.ln[2], 3);

    OS_ClearNode(node);
    OS_ClearXML(&xml);
    unlink(xml_file_name);
    return 1;
}

int test_invalid_file() {
    OS_XML xml;
    w_assert_int_ne(OS_ReadXML("invalid_file.inv", &xml), 0);
    w_assert_str_eq(xml.err, "XMLERR: File 'invalid_file.inv' not found.");
    w_assert_int_eq(xml.err_line, 0);

    OS_ClearXML(&xml);
    return 1;
}

int test_unclosed_node() {
    char xml_file_name[256];
    create_xml_file("<root>", xml_file_name, 256);
    OS_XML xml;
    w_assert_int_ne(OS_ReadXML(xml_file_name, &xml), 0);
    w_assert_str_eq(xml.err, "XMLERR: End of file and some elements were not closed.");
    w_assert_int_eq(xml.err_line, 1);

    OS_ClearXML(&xml);
    unlink(xml_file_name);
    return 1;
}

int test_unclosed_second_node() {
    char xml_file_name[256];
    create_xml_file("<root></root2>", xml_file_name, 256);
    OS_XML xml;
    w_assert_int_ne(OS_ReadXML(xml_file_name, &xml), 0);
    w_assert_str_eq(xml.err, "XMLERR: Element 'root' not closed.");
    w_assert_int_eq(xml.err_line, 1);

    OS_ClearXML(&xml);
    unlink(xml_file_name);
    return 1;
}

int test_unclosed_comment() {
    char xml_file_name[256];
    create_xml_file("<!-- comment", xml_file_name, 256);
    OS_XML xml;
    w_assert_int_ne(OS_ReadXML(xml_file_name, &xml), 0);
    w_assert_str_eq(xml.err, "XMLERR: Comment not closed.");
    w_assert_int_eq(xml.err_line, 1);

    OS_ClearXML(&xml);
    unlink(xml_file_name);
    return 1;
}

int test_node_not_opened() {
    char xml_file_name[256];
    create_xml_file("</root>", xml_file_name, 256);
    OS_XML xml;
    w_assert_int_ne(OS_ReadXML(xml_file_name, &xml), 0);
    w_assert_str_eq(xml.err, "XMLERR: Element not opened.");
    w_assert_int_eq(xml.err_line, 1);

    OS_ClearXML(&xml);
    unlink(xml_file_name);
    return 1;
}

int test_unclosed_attribute() {
    char xml_file_name[256];
    create_xml_file("<root attr=\"attribute></root>", xml_file_name, 256);
    OS_XML xml;
    w_assert_int_ne(OS_ReadXML(xml_file_name, &xml), 0);
    w_assert_str_eq(xml.err, "XMLERR: Attribute 'attr' not closed.");
    w_assert_int_eq(xml.err_line, 1);

    OS_ClearXML(&xml);
    unlink(xml_file_name);
    return 1;
}

int test_unquoted_attribute() {
    char xml_file_name[256];
    create_xml_file("<root attr=attribute></root>", xml_file_name, 256);
    OS_XML xml;
    w_assert_int_ne(OS_ReadXML(xml_file_name, &xml), 0);
    w_assert_str_eq(xml.err, "XMLERR: Attribute 'attr' not followed by a \" or '.");
    w_assert_int_eq(xml.err_line, 1);

    OS_ClearXML(&xml);
    unlink(xml_file_name);
    return 1;
}

int test_infinite_attribute() {
    char xml_file_name[256];
    create_xml_file("<root attr", xml_file_name, 256);
    OS_XML xml;
    w_assert_int_ne(OS_ReadXML(xml_file_name, &xml), 0);
    w_assert_str_eq(xml.err, "XMLERR: End of file while reading an attribute.");
    w_assert_int_eq(xml.err_line, 1);

    OS_ClearXML(&xml);
    unlink(xml_file_name);
    return 1;
}

int test_invalid_variable_name() {
    char xml_file_name[256];
    create_xml_file("<var test=\"test\"></var>", xml_file_name, 256);
    OS_XML xml;
    w_assert_int_eq(OS_ReadXML(xml_file_name, &xml), 0);
    w_assert_int_ne(OS_ApplyVariables(&xml), 0);
    w_assert_str_eq(xml.err, "XMLERR: Only \"name\" is allowed as an attribute for a variable.");
    w_assert_int_eq(xml.err_line, 1);

    OS_ClearXML(&xml);
    unlink(xml_file_name);
    return 1;
}

int test_invalid_variable_double_max_size() {
    char xml_file_name[256];
    char overflow_string[XML_VARIABLE_MAXSIZE + 10];
    memset(overflow_string, 'c', XML_VARIABLE_MAXSIZE + 9);
    overflow_string[XML_VARIABLE_MAXSIZE + 9] = '\0';

    char xml_string[2 * XML_VARIABLE_MAXSIZE];
    snprintf(xml_string, 2 * XML_VARIABLE_MAXSIZE - 1, "<var name=\"%s\">test</var><root/>", overflow_string);
    create_xml_file(xml_string, xml_file_name, 256);
    OS_XML xml;
    w_assert_int_eq(OS_ReadXML(xml_file_name, &xml), 0);
    w_assert_int_ne(OS_ApplyVariables(&xml), 0);
    w_assert_str_eq(xml.err, "XMLERR: Invalid variable name size.");
    w_assert_int_eq(xml.err_line, 1);

    OS_ClearXML(&xml);
    unlink(xml_file_name);
    return 1;
}

int test_invalid_variable_triple_max_size() {
    char xml_file_name[256];
    char overflow_string[XML_VARIABLE_MAXSIZE + 10];
    memset(overflow_string, 'c', XML_VARIABLE_MAXSIZE + 9);
    overflow_string[XML_VARIABLE_MAXSIZE + 9] = '\0';

    char xml_string[3 * XML_VARIABLE_MAXSIZE];
    snprintf(xml_string, 3 * XML_VARIABLE_MAXSIZE - 1, "<var name=\"%s\">test</var><test>$%s</test>", overflow_string, overflow_string);
    create_xml_file(xml_string, xml_file_name, 256);
    OS_XML xml;
    w_assert_int_eq(OS_ReadXML(xml_file_name, &xml), 0);
    w_assert_int_ne(OS_ApplyVariables(&xml), 0);
    w_assert_str_eq(xml.err, "XMLERR: Invalid variable name size.");
    w_assert_int_eq(xml.err_line, 1);

    OS_ClearXML(&xml);
    unlink(xml_file_name);
    return 1;
}

int test_empty_attribute() {
    char xml_file_name[256];
    create_xml_file("<root attr=", xml_file_name, 256);
    OS_XML xml;
    w_assert_int_ne(OS_ReadXML(xml_file_name, &xml), 0);
    w_assert_str_eq(xml.err, "XMLERR: Attribute 'attr' not followed by a \" or '.");
    w_assert_int_eq(xml.err_line, 1);

    OS_ClearXML(&xml);
    unlink(xml_file_name);
    return 1;
}

int test_invalid_attribute_start() {
    char xml_file_name[256];
    create_xml_file("<root attr=  test\"test\"/>", xml_file_name, 256);
    OS_XML xml;
    w_assert_int_ne(OS_ReadXML(xml_file_name, &xml), 0);
    w_assert_str_eq(xml.err, "XMLERR: Attribute 'attr' not followed by a \" or '.");
    w_assert_int_eq(xml.err_line, 1);

    OS_ClearXML(&xml);
    unlink(xml_file_name);
    return 1;
}

int test_invalid_attribute_closing() {
    char xml_file_name[256];
    create_xml_file("<root attr=''", xml_file_name, 256);
    OS_XML xml;
    w_assert_int_ne(OS_ReadXML(xml_file_name, &xml), 0);
    w_assert_str_eq(xml.err, "XMLERR: Bad attribute closing for 'attr'=''.");
    w_assert_int_eq(xml.err_line, 1);

    OS_ClearXML(&xml);
    unlink(xml_file_name);
    return 1;
}

int test_wrong_variable_name() {
    char xml_file_name[256];
    create_xml_file("<var name=\"test\">content</var><root>$var</root>", xml_file_name, 256);
    OS_XML xml;
    w_assert_int_eq(OS_ReadXML(xml_file_name, &xml), 0);
    w_assert_int_ne(OS_ApplyVariables(&xml), 0);
    w_assert_str_eq(xml.err, "XMLERR: Unknown variable: 'var'.");
    w_assert_int_eq(xml.err_line, 1);

    OS_ClearXML(&xml);
    unlink(xml_file_name);
    return 1;
}

int test_unknown_variable() {
    return assert_os_xml_eq("<root>$var</root>",
                     "<root>$var</root>");
}

int test_invalid_attribute_closing_no_space() {
    char xml_file_name[256];
    create_xml_file("<root attr='test'test/>", xml_file_name, 256);
    OS_XML xml;
    w_assert_int_ne(OS_ReadXML(xml_file_name, &xml), 0);
    w_assert_str_eq(xml.err, "XMLERR: Bad attribute closing for 'attr'='test'.");
    w_assert_int_eq(xml.err_line, 1);

    OS_ClearXML(&xml);
    unlink(xml_file_name);
    return 1;
}

int test_invalid_attribute_closing_no_second_quote() {
    char xml_file_name[256];
    create_xml_file("<root attr='", xml_file_name, 256);
    OS_XML xml;
    w_assert_int_ne(OS_ReadXML(xml_file_name, &xml), 0);
    w_assert_str_eq(xml.err, "XMLERR: End of file while reading an attribute.");
    w_assert_int_eq(xml.err_line, 1);

    OS_ClearXML(&xml);
    unlink(xml_file_name);
    return 1;
}

int test_duplicated_attribute() {
    char xml_file_name[256];
    create_xml_file("<root attr='test' attr2='test' attr='test123'></root>", xml_file_name, 256);
    OS_XML xml;
    w_assert_int_ne(OS_ReadXML(xml_file_name, &xml), 0);
    w_assert_str_eq(xml.err, "XMLERR: Attribute 'attr' already defined.");
    w_assert_int_eq(xml.err_line, 1);

    OS_ClearXML(&xml);
    unlink(xml_file_name);
    return 1;
}

int test_no_attribute_value() {
    char xml_file_name[256];
    create_xml_file("<root attr></root>", xml_file_name, 256);
    OS_XML xml;
    w_assert_int_ne(OS_ReadXML(xml_file_name, &xml), 0);
    w_assert_str_eq(xml.err, "XMLERR: Attribute 'attr' has no value.");
    w_assert_int_eq(xml.err_line, 1);

    OS_ClearXML(&xml);
    unlink(xml_file_name);
    return 1;
}

int test_no_first_attribute_value() {
    char xml_file_name[256];
    create_xml_file("<root attr attr2='test'></root>", xml_file_name, 256);
    OS_XML xml;
    w_assert_int_ne(OS_ReadXML(xml_file_name, &xml), 0);
    w_assert_str_eq(xml.err, "XMLERR: Attribute 'attr' has no value.");
    w_assert_int_eq(xml.err_line, 1);

    OS_ClearXML(&xml);
    unlink(xml_file_name);
    return 1;
}

int test_os_elements_exists() {
    char xml_file_name[256];
    create_xml_file("<root></root><root1/><root/>", xml_file_name, 256);
    OS_XML xml;
    w_assert_int_eq(OS_ReadXML(xml_file_name, &xml), 0);
    w_assert_int_eq(OS_ApplyVariables(&xml), 0);
    w_assert_int_eq(OS_RootElementExist(&xml, "root"), 2);
    w_assert_int_eq(OS_RootElementExist(&xml, "root1"), 1);
    w_assert_int_eq(OS_RootElementExist(&xml, "root2"), 0);

    OS_ClearXML(&xml);
    unlink(xml_file_name);
    return 1;
}

int test_os_get_one_content_for_element() {
    char xml_file_name[256];
    create_xml_file("<root><child>test</child><child>test2</child><child2>test</child2></root>", xml_file_name, 256);
    OS_XML xml;
    w_assert_int_eq(OS_ReadXML(xml_file_name, &xml), 0);
    w_assert_int_eq(OS_ApplyVariables(&xml), 0);
    const char *xml_path1[] = { "root", "child", NULL };
    const char *xml_path2[] = { "root", "child2", NULL };
    const char *xml_path3[] = { "root", "child3", NULL };
    char *content1, *content2;
    w_assert_str_eq(content1 = OS_GetOneContentforElement(&xml, xml_path1), "test");
    w_assert_str_eq(content2 = OS_GetOneContentforElement(&xml, xml_path2), "test");
    w_assert_ptr_eq(OS_GetOneContentforElement(&xml, xml_path3), NULL);

    free(content1);
    free(content2);
    OS_ClearXML(&xml);
    unlink(xml_file_name);
    return 1;
}

int test_os_write_xml_success() {
    const char *xml_path[] = { "root", "child", NULL };
    if(!assert_ox_xml_write_eq(
        "<root><child>test</child></root>",
        "<root><child>test_new</child></root>",
        xml_path, "test", "test_new")){
        return 0;
    }
    if(!assert_ox_xml_write_eq(
        "<root><child>test</child></root>",
        "<root><child>test</child></root>",
        xml_path, "test", "test")){
        return 0;
    }
    if(!assert_ox_xml_write_eq(
        "<root><child></child></root>",
        "<root><child>test</child></root>",
        xml_path, "test", "test")){
        return 0;
    }
    if(!assert_ox_xml_write_eq(
        "<root2><child></child></root2>",
        "<root2><child></child></root2><root>\n <child>test</child></root>",
        xml_path, NULL, "test")){
        return 0;
    }
    return 1;
}

int test_os_write_xml_failures() {
    char xml_in_file_name[256];
    create_xml_file("<root><child>test</child></root>", xml_in_file_name, 256);
    char xml_out_file_name[256];
    create_xml_file("", xml_out_file_name, 256);
    const char *xml_path[] = { "root", "child", NULL };

    w_assert_int_eq(OS_WriteXML("invalid", xml_out_file_name, xml_path, "test", "test_new"), XMLW_NOIN);
    w_assert_int_eq(OS_WriteXML(xml_in_file_name, "??invalid<<!!\"\"//\\\\", xml_path, "test", "test_new"), XMLW_NOOUT);

    unlink(xml_in_file_name);
    unlink(xml_out_file_name);
    return 1;
}

int test_os_get_attribute_content() {
    char xml_file_name[256];
    create_xml_file("<root attr=\"value\" attr2=\"value1\"></root>", xml_file_name, 256);
    OS_XML xml;
    w_assert_int_eq(OS_ReadXML(xml_file_name, &xml), 0);
    w_assert_int_eq(OS_ApplyVariables(&xml), 0);
    const char *xml_path1[] = { "root", NULL };
    const char *xml_path2[] = { NULL };
    char *content1, *content2, *content3, *content4;
    w_assert_str_eq(content1 = OS_GetAttributeContent(&xml, xml_path1, "attr"), "value");
    w_assert_str_eq(content2 = OS_GetAttributeContent(&xml, xml_path1, "attr2"), "value1");
    w_assert_str_eq(content3 = OS_GetAttributeContent(&xml, xml_path1, "attr3"), "");
    w_assert_str_eq(content4 = OS_GetAttributeContent(&xml, xml_path1, NULL), "");
    w_assert_ptr_eq(OS_GetAttributeContent(&xml, xml_path2, NULL), NULL);


    free(content1);
    free(content2);
    free(content3);
    free(content4);
    OS_ClearXML(&xml);
    unlink(xml_file_name);
    return 1;
}

int test_os_get_contents() {
    char xml_file_name[256];
    create_xml_file("<root>value</root><root>value2</root><root2>value</root2>", xml_file_name, 256);
    OS_XML xml;
    w_assert_int_eq(OS_ReadXML(xml_file_name, &xml), 0);
    w_assert_int_eq(OS_ApplyVariables(&xml), 0);
    const char *xml_path1[] = { "root", NULL };
    const char *xml_path2[] = { "root2", NULL };
    char **content1, **content2;
    w_assert_ptr_ne(content1 = OS_GetContents(&xml, xml_path1), NULL);
    w_assert_str_eq(content1[0], "value");
    w_assert_str_eq(content1[1], "value2");
    w_assert_ptr_eq(content1[2], NULL);

    w_assert_ptr_ne(content2 = OS_GetContents(&xml, xml_path2), NULL);
    w_assert_str_eq(content2[0], "value");
    w_assert_ptr_eq(content2[1], NULL);

    w_assert_ptr_eq(OS_GetContents(&xml, NULL), NULL);

    int i = 0;
    while (content1[i]) {
        free(content1[i++]);
    }
    free(content1);

    i = 0;
    while (content2[i]) {
        free(content2[i++]);
    }
    free(content2);
    OS_ClearXML(&xml);
    unlink(xml_file_name);
    return 1;
}

int test_os_get_element_content() {
    char xml_file_name[256];
    create_xml_file("<root>value</root>", xml_file_name, 256);
    OS_XML xml;
    w_assert_int_eq(OS_ReadXML(xml_file_name, &xml), 0);
    w_assert_int_eq(OS_ApplyVariables(&xml), 0);
    const char *xml_path[] = { "root", NULL };
    char **content;
    w_assert_ptr_ne(content = OS_GetElementContent(&xml, xml_path), NULL);
    w_assert_str_eq(content[0], "value");
    w_assert_ptr_eq(content[1], NULL);

    int i = 0;
    while (content[i]) {
        free(content[i++]);
    }
    free(content);
    OS_ClearXML(&xml);
    unlink(xml_file_name);
    return 1;
}

int test_os_get_elements() {
    char xml_file_name[256];
    create_xml_file("<root><child1/><child2/></root>", xml_file_name, 256);
    OS_XML xml;
    w_assert_int_eq(OS_ReadXML(xml_file_name, &xml), 0);
    w_assert_int_eq(OS_ApplyVariables(&xml), 0);
    const char *xml_path[] = { "root", NULL };
    char **content1, **content2;
    w_assert_ptr_ne(content1 = OS_GetElements(&xml, xml_path), NULL);
    w_assert_str_eq(content1[0], "child1");
    w_assert_str_eq(content1[1], "child2");
    w_assert_ptr_eq(content1[2], NULL);
    w_assert_ptr_ne(content2 = OS_GetElements(&xml, NULL), NULL);
    w_assert_str_eq(content2[0], "root");
    w_assert_ptr_eq(content2[1], NULL);
    const char *xml_path2[] = { NULL };
    w_assert_ptr_eq(OS_GetElements(&xml,  xml_path2), NULL);

    int i = 0;
    while (content1[i]) {
        free(content1[i++]);
    }
    free(content1);
    i = 0;
    while (content2[i]) {
        free(content2[i++]);
    }
    free(content2);
    OS_ClearXML(&xml);
    unlink(xml_file_name);
    return 1;
}

int test_os_get_attributes() {
    char xml_file_name[256];
    create_xml_file("<root attr1=\"1\" attr2=\"2\"></root>", xml_file_name, 256);
    OS_XML xml;
    w_assert_int_eq(OS_ReadXML(xml_file_name, &xml), 0);
    w_assert_int_eq(OS_ApplyVariables(&xml), 0);
    const char *xml_path[] = { "root", NULL };
    char **content;
    w_assert_ptr_ne(content = OS_GetAttributes(&xml, xml_path), NULL);
    w_assert_str_eq(content[0], "attr1");
    w_assert_str_eq(content[1], "attr2");
    w_assert_ptr_eq(content[2], NULL);

    int i = 0;
    while (content[i]) {
        free(content[i++]);
    }
    free(content);
    OS_ClearXML(&xml);
    unlink(xml_file_name);
    return 1;
}

int test_node_name_overflow() {
    char xml_file_name[256];
    char overflow_string[XML_MAXSIZE + 10];
    memset(overflow_string, 'c', XML_MAXSIZE + 9);
    overflow_string[XML_MAXSIZE + 9] = '\0';

    char xml_string[2 * XML_MAXSIZE];
    snprintf(xml_string, 2 * XML_MAXSIZE - 1, "<%s/>", overflow_string);
    create_xml_file(xml_string, xml_file_name, 256);
    OS_XML xml;
    w_assert_int_ne(OS_ReadXML(xml_file_name, &xml), 0);
    w_assert_str_eq(xml.err, "XMLERR: String overflow.");
    w_assert_int_eq(xml.err_line, 1);

    OS_ClearXML(&xml);
    unlink(xml_file_name);
    return 1;
}

int test_node_value_overflow() {
    char xml_file_name[256];
    char overflow_string[XML_MAXSIZE + 10];
    memset(overflow_string, 'c', XML_MAXSIZE + 9);
    overflow_string[XML_MAXSIZE + 9] = '\0';

    char xml_string[2 * XML_MAXSIZE];
    snprintf(xml_string, 2 * XML_MAXSIZE - 1, "<test>%s</test>", overflow_string);
    create_xml_file(xml_string, xml_file_name, 256);
    OS_XML xml;
    w_assert_int_ne(OS_ReadXML(xml_file_name, &xml), 0);
    w_assert_str_eq(xml.err, "XMLERR: String overflow.");
    w_assert_int_eq(xml.err_line, 1);

    OS_ClearXML(&xml);
    unlink(xml_file_name);
    return 1;
}

int test_node_attribute_name_overflow() {
    char xml_file_name[256];
    char overflow_string[XML_MAXSIZE + 10];
    memset(overflow_string, 'c', XML_MAXSIZE + 9);
    overflow_string[XML_MAXSIZE + 9] = '\0';

    char xml_string[2 * XML_MAXSIZE];
    snprintf(xml_string, 2 * XML_MAXSIZE - 1, "<test %s=\"test\">test</test>", overflow_string);
    create_xml_file(xml_string, xml_file_name, 256);
    OS_XML xml;
    w_assert_int_ne(OS_ReadXML(xml_file_name, &xml), 0);
    w_assert_str_eq(xml.err, "XMLERR: Overflow attempt at attribute 'cccccccccccccccccccc'.");
    w_assert_int_eq(xml.err_line, 1);

    OS_ClearXML(&xml);
    unlink(xml_file_name);
    return 1;
}

int test_node_attribute_value_overflow() {
    char xml_file_name[256];
    char overflow_string[XML_MAXSIZE + 10];
    memset(overflow_string, 'c', XML_MAXSIZE + 9);
    overflow_string[XML_MAXSIZE + 9] = '\0';

    char xml_string[2 * XML_MAXSIZE];
    snprintf(xml_string, 2 * XML_MAXSIZE - 1, "<test test=\"%s\">test</test>", overflow_string);
    create_xml_file(xml_string, xml_file_name, 256);
    OS_XML xml;
    w_assert_int_ne(OS_ReadXML(xml_file_name, &xml), 0);
    w_assert_str_eq(xml.err, "XMLERR: Overflow attempt at attribute 'test'.");
    w_assert_int_eq(xml.err_line, 1);

    OS_ClearXML(&xml);
    unlink(xml_file_name);
    return 1;
}

int main(void) {

    printf(CYELLOW"\n\n   STARTING TEST - OS_XML   \n\n" CEND);

    // Simple XML node test
    TAP_TEST_MSG(test_simple_nodes(), "Simple XML node test.");

    // Multiple XML nodes test
    TAP_TEST_MSG(test_multiple_nodes(), "Multiple XML nodes test.");

    // Childen on XML nodes test
    TAP_TEST_MSG(test_children(), "Childen on XML nodes test.");

    // Childen on XML nodes test
    TAP_TEST_MSG(test_multiple_content(), "Multiple content on XML node test.");

    // Attributes inside XML test
    TAP_TEST_MSG(test_attributes(), "Attributes inside XML test.");

    // Variables inside XML test
    TAP_TEST_MSG(test_variables(), "Variables inside XML test.");

    // Comments inside XML test
    TAP_TEST_MSG(test_comments(), "Comments inside XML test.");

    // Special chars inside XML test
    TAP_TEST_MSG(test_special_chars(), "Special chars inside XML test.");

    // Line counter inside XML test
    TAP_TEST_MSG(test_line_counter(), "Line counter inside XML test.");

    // Invalid XML test
    TAP_TEST_MSG(test_invalid_file(), "Invalid XML test.");

    // Unclosed node XML test
    TAP_TEST_MSG(test_unclosed_node(), "Unclosed node inside XML test.");

    // Unclosed second node XML test
    TAP_TEST_MSG(test_unclosed_second_node(), "Unclosed second node inside XML test.");

    // Unclosed comment inside XML test
    TAP_TEST_MSG(test_unclosed_comment(), "Unclosed comment inside XML test.");

    // Node not opened inside XML test
    TAP_TEST_MSG(test_node_not_opened(), "Node not opened inside XML test.");

    // Unclosed attribute inside XML test
    TAP_TEST_MSG(test_unclosed_attribute(), "Unclosed attribute inside XML test.");

    // Unquoted attribute inside XML test
    TAP_TEST_MSG(test_unquoted_attribute(), "Unquoted attribute inside XML test.");

    // Infinite attribute inside XML test
    TAP_TEST_MSG(test_infinite_attribute(), "Infinite attribute inside XML test.");

    // Invalid variable name inside XML test
    TAP_TEST_MSG(test_invalid_variable_name(), "Invalid variable name inside XML test.");

    // Invalid variable name (2*MAX_SIZE) inside XML test
    TAP_TEST_MSG(test_invalid_variable_double_max_size(), "Invalid variable name (2*MAX_SIZE) inside XML test.");

    // Invalid variable name (3*MAX_SIZE) inside XML test
    TAP_TEST_MSG(test_invalid_variable_triple_max_size(), "Invalid variable name (2*MAX_SIZE) inside XML test.");

    // Empty attribute inside XML test
    TAP_TEST_MSG(test_empty_attribute(), "Empty attribute inside XML test.");

    // Empty attribute start inside XML test
    TAP_TEST_MSG(test_invalid_attribute_start(), "Empty attribute start inside XML test.");

    // Invalid attribute closing inside XML test
    TAP_TEST_MSG(test_invalid_attribute_closing(), "Invalid attribute closing inside XML test.");

    // Wrong variable name inside XML test
    TAP_TEST_MSG(test_wrong_variable_name(), "Wrong variable name inside XML test.");

    // Unknown variable inside XML test
    TAP_TEST_MSG(test_unknown_variable(), "Unknown variable inside XML test.");

    // Invalid attribute closing (no space) inside XML test
    TAP_TEST_MSG(test_invalid_attribute_closing_no_space(), "Invalid attribute closing (no space) inside XML test.");

    // Invalid attribute closing (no second quote) inside XML test
    TAP_TEST_MSG(test_invalid_attribute_closing_no_second_quote(), "Invalid attribute closing (no second quote) inside XML test.");

    // Duplicated attribute inside XML test
    TAP_TEST_MSG(test_duplicated_attribute(), "Duplicated attribute inside XML test.");

    // No attribute value inside XML test
    TAP_TEST_MSG(test_no_attribute_value(), "No attribute value inside XML test.");

    // No first attribute value inside XML test
    TAP_TEST_MSG(test_no_first_attribute_value(), "No first attribute value inside XML test.");

    // OS_RootElementExist test
    TAP_TEST_MSG(test_os_elements_exists(), "OS_RootElementExist test.");

    // OS_GetOneContentforElement test
    TAP_TEST_MSG(test_os_get_one_content_for_element(), "OS_GetOneContentforElement test.");

    // OS_WriteXML test
    TAP_TEST_MSG(test_os_write_xml_success(), "OS_WriteXML test.");

    // OS_WriteXML failures test
    TAP_TEST_MSG(test_os_write_xml_failures(), "OS_WriteXML failures test.");

    // OS_GetAttributeContent test
    TAP_TEST_MSG(test_os_get_attribute_content(), "OS_GetAttributeContent test.");

    // OS_GetContents test
    TAP_TEST_MSG(test_os_get_contents(), "OS_GetContents test.");

    // OS_GetElementContent test
    TAP_TEST_MSG(test_os_get_element_content(), "OS_GetElementContent test.");

    // OS_GetElements test
    TAP_TEST_MSG(test_os_get_elements(), "OS_GetElements test.");

    // OS_GetAttributes test
    TAP_TEST_MSG(test_os_get_attributes(), "OS_GetAttributes test.");

    // Node name inside XML overflow test
    TAP_TEST_MSG(test_node_name_overflow(), "Node name inside XML overflow test.");

    // Node value inside XML overflow test
    TAP_TEST_MSG(test_node_value_overflow(), "Node value inside XML overflow test.");

    // Node attribute name inside XML overflow test
    TAP_TEST_MSG(test_node_attribute_name_overflow(), "Node attribute name inside XML overflow test.");

    // Node attribute value inside XML overflow test
    TAP_TEST_MSG(test_node_attribute_value_overflow(), "Node attribute value inside XML overflow test.");

    TAP_PLAN;
    TAP_SUMMARY;
    printf(CYELLOW "\n   ENDING TEST  - OS_XML   \n\n" CEND);
    return 0;
}