#ifndef WFOPEN_H
#define WFOPEN_H


/**
 * @brief Open file normally in Linux, allow read/write/delete in Windows.
 *
 * @param pathname Path of the file.
 * @param mode Open mode.
 * @return File pointer.
 */

FILE * wfopen(const char * pathname, const char * modes);

#endif