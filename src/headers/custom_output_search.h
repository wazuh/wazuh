/*
 * custom_output_search.h
 *
 *  Created on: 10/10/2012
 *      Author: crosa
 */

#ifndef CUSTOM_OUTPUT_SEARCH_H_
#define CUSTOM_OUTPUT_SEARCH_H_
/** char *searchAndReplace(char* orig, char* search, char*value)
 *  Searchs for 'search' on orig's string and replaces it by value.
 *  Returns NULL on error, otherwise returns the orig string with the replacements.
 */
char * searchAndReplace(const char* orig, const char* search, const char*value);

/** char* escape_newlines(char *orig);
 * Escape the newlines characters
 * Returns NULL on error, otherwise returns a new allocated string.
 */
char* escape_newlines(const char *orig);


#endif /* CUSTOM_OUTPUT_SEARCH_H_ */
