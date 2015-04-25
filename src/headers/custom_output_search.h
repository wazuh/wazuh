#ifndef CUSTOM_OUTPUT_SEARCH_H_
#define CUSTOM_OUTPUT_SEARCH_H_

/* Search for 'search' in string and replaces it by value
 * Returns NULL on error, otherwise returns the orig string with the replacements
 */
char *searchAndReplace(const char *orig, const char *search, const char *value) __attribute__((nonnull));

/* Escape the newline characters
 * Returns NULL on error, otherwise returns a newly allocated string
 */
char *escape_newlines(const char *orig) __attribute__((nonnull));

#endif /* CUSTOM_OUTPUT_SEARCH_H_ */

