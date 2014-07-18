#include "shared.h"


char * searchAndReplace(const char* orig, const char* search, const char*value)
{
  char *p;
  size_t total_len = strlen(orig);
  size_t token_len = strlen(search);
  size_t value_len = strlen(value);

  int inx_start = 0;
  char * tmp = NULL;
  int tmp_offset = 0;
  int total_bytes_allocated = 0;
  int from = 0;
  p = strstr(orig, search);
  if(p==NULL)
  {
    os_strdup(orig,tmp);

    return tmp;
  }
  if (value==NULL)
  {
    value="";
  }
  inx_start = p - orig;

  while (p != NULL)
  {
    if (inx_start > 0)
    {
      if (tmp == NULL)
      {
        int len_to_add = (inx_start);

        tmp = (char*) malloc(sizeof(char) * len_to_add);
        total_bytes_allocated += len_to_add;

        strncpy(tmp, orig + tmp_offset, inx_start);
        tmp_offset = inx_start;
      }

      total_bytes_allocated += value_len;
      tmp = (char*) realloc(tmp, total_bytes_allocated);

      strncpy(tmp + tmp_offset, value, value_len);
      tmp_offset += value_len;


      p = strstr(orig + inx_start + token_len, search);

      if(p!=NULL)
      {
        inx_start = p - orig;
        from = inx_start + token_len;
        if (inx_start - tmp_offset > 0)
        {
          total_bytes_allocated += inx_start - from;
          tmp = (char*) realloc(tmp, total_bytes_allocated);
          strncpy(tmp + tmp_offset, orig + from, inx_start - from);
          tmp_offset += inx_start - from;
        }
      }//No more coincidences.
      else
      {
        from = inx_start + token_len;
      }
    }

  }
  if ((from  < total_len) && from>0)
  {
    total_bytes_allocated += total_len - from;//((from - (int)token_len) + (int)value_len);
    tmp = (char*) realloc(tmp, total_bytes_allocated+1);
    strncpy(tmp + tmp_offset, orig + from, total_len - from);
  }
  tmp[total_bytes_allocated]='\0';

  return tmp;
}

//escape newlines characters. Returns a new allocated string.
char* escape_newlines(const char *orig)
{
  const char *ptr;
  char *ret, *retptr;
  size_t size;

  ptr = orig;
  size = 1;
  while (*ptr)
  {
    if ((*ptr == '\n') ||(*ptr == '\r'))
      size += 2;
    else
      size += 1;
    ptr++;
  }

  ret = malloc (size);
  ptr = orig;
  retptr = ret;
  while (*ptr) {
    if (*ptr == '\n') {
      *retptr = '\\';
      *(retptr+1) = 'n';
      retptr += 2;
    }
    else if (*ptr == '\r') {
      *retptr = '\\';
      *(retptr+1) = 'n';
      retptr += 2;
    }
    else {
      *retptr = *ptr;
      retptr ++;
    }
    ptr++;
  }
  *retptr = '\0';

  return ret;
}
