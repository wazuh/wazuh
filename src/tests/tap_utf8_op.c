#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include "../headers/utf8_op.h"
#include "tap.h"

const char utf8_str[] = {
    0x6d,                    // m
    0xc3, 0x9f,              // ß
    0xc3, 0x86,              // Æ
    0xc3, 0x91,              // Ñ
    0x40,                    // @
    0xc2, 0xa3,              // £
    0xc3, 0xbf,              // ÿ
    0x5a,                    // Z
    0xe2, 0x84, 0xaa,        // K
    0xe1, 0x9a, 0x83,        // ᚃ
    0xf3, 0xa0, 0x80, 0xb0,  //
    0xe2, 0x82, 0xac,        // €
    0x3a,                    // :
    0};

const char ascii_str[] = {35, 58, 75, 64, 109, 146, 164, 225, 0};

const char invalid_utf8_str[] = {
    0xc2, 0xa9,              // ©
    0xc2, 0xb6,              // ¶
    0xc2, 0xbf,              // ¿
    0xc0, 0xca,              // INVALID
    0x45,                    // E
    0xc5, 0x98,              // Ř
    0xc3, 0xaa,              // ê
    0x64,                    // d
    0};

// Check valid UTF-8 string.
int test_w_utf8_valid() {
    return w_utf8_valid(utf8_str);
}

// Check invalid UTF-8 string
int test_w_utf8_valid_nok() {
    return !w_utf8_valid(invalid_utf8_str);
}

// Check ASCII string
int test_w_utf8_valid_ascii() {
    return !w_utf8_valid(ascii_str);
}

// Get invalid UTF-8 character
int test_w_utf8_drop() {
    const char * ptr;
    ptr = w_utf8_drop(invalid_utf8_str);
    return ((*ptr ^ (char)0xc0) == 0 && (*(++ptr) ^ (char)0xca) == 0);
}

// Remove invalid characters from UTF-8 string
int test_w_utf8_filter() {
    char *string;
    int ret = 0;
    string = w_utf8_filter(invalid_utf8_str, 0);
    if (w_utf8_valid(string)) {
        ret = 1;
    }
    free(string);
    return ret;
}

// Replace invalid characters from UTF-8 string
int test_w_utf8_filter_rep() {
    char *string;
    int ret = 0;
    string = w_utf8_filter(invalid_utf8_str, 1);
    if (w_utf8_valid(string)) {
        ret = 1;
    }
    free(string);
    return ret;
}

int main(void) {

    printf("\n\n   STARTING TEST - UTF8_OP   \n\n");

    TAP_TEST_MSG(test_w_utf8_valid(), "Test valid UTF-8 string.");

    TAP_TEST_MSG(test_w_utf8_valid_nok(), "Test invalid UTF-8 string.");

    TAP_TEST_MSG(test_w_utf8_valid_ascii(), "Test ASCII string.");

    TAP_TEST_MSG(test_w_utf8_drop(), "Get invalid UTF-8 character.");

    TAP_TEST_MSG(test_w_utf8_filter(), "Remove invalid characters from UTF-8 string.");

    TAP_TEST_MSG(test_w_utf8_filter_rep(), "Replace invalid characters from UTF-8 string.");

    TAP_PLAN;
    TAP_SUMMARY;

    printf("\n   ENDING TEST - UTF8_OP   \n\n");
    return 0;

}
