/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "os_xml.h"
#include "os_xml_internal.h"

/* Prototypes */
static char **_GetElements(const OS_XML *_lxml, const char **element_name, XML_TYPE type) __attribute__((nonnull(1)));
static char **_GetElementContent(OS_XML *_lxml, const char **element_name, const char *attr) __attribute__((nonnull(1, 2)));


/* Check if a element exists
 * The element_name must be NULL terminated (last char)
 */
unsigned int OS_ElementExist(const OS_XML *_lxml, const char **element_name)
{
    unsigned int i = 0, j = 0, matched = 0, totalmatch = 0;

    if (element_name[0] == NULL) {
        return (0);
    }

    for (i = 0, j = 0; i < _lxml->cur; i++) {
        if (element_name[j] == NULL) {
            j = 0;
        }
        if ((_lxml->tp[i] == XML_ELEM) && (_lxml->rl[i] == j)) {
            if (strcmp(_lxml->el[i], element_name[j]) == 0) {
                j++;
                matched = 1;
                if (element_name[j] == NULL) {
                    j = 0;
                    totalmatch++;
                }
                continue;
            }
        }
        if ((matched == 1) && (j > _lxml->rl[i]) &&
                (_lxml->tp[i] == XML_ELEM)) {
            j = 0;
            matched = 0;
        }
    }
    return (totalmatch);
}

/* Check if a root element exists */
unsigned int OS_RootElementExist(const OS_XML *_lxml, const char *element_name)
{
    const char *(elements[]) = {element_name, NULL};
    return (OS_ElementExist(_lxml, elements));
}

/* Get the attributes of the element_name */
char **OS_GetAttributes(const OS_XML *_lxml, const char **element_name)
{
    return (_GetElements(_lxml, element_name, XML_ATTR));
}

/* Get the elements children of the element_name */
char **OS_GetElements(const OS_XML *_lxml, const char **element_name)
{
    return (_GetElements(_lxml, element_name, XML_ELEM));
}

/* Get the elements or attributes (internal use) */
static char **_GetElements(const OS_XML *_lxml, const char **element_name, XML_TYPE type)
{
    unsigned i = 0, j = 0, k = 0, matched = 0, ready = 0;
    char **ret = NULL;
    char **ret_tmp = NULL;

    if ((type == XML_ELEM) && (element_name == NULL)) {
        ready = 1;
    }

    for (i = 0, j = 0; i < _lxml->cur; i++) {
        if ((ready != 1) && (element_name[j] == NULL)) {
            if (matched == 1) {
                ready = 1;
            } else {
                break;
            }
        }

        if (j > 16) {
            return (ret);
        }

        if ((ready == 1) && (_lxml->tp[i] == type)) {
            if (((type == XML_ATTR) && (_lxml->rl[i] == j - 1)
                    && (_lxml->el[i] != NULL)) ||
                    ((type == XML_ELEM) && (_lxml->rl[i] == j) &&
                     (_lxml->el[i] != NULL))) {
                size_t el_size = strlen(_lxml->el[i]) + 1;
                ret_tmp = (char **)realloc(ret, (k + 2) * sizeof(char *));
                if (ret_tmp == NULL) {
                    goto fail;
                }
                ret = ret_tmp;
                ret[k + 1] = NULL;
                ret[k] = (char *)calloc(el_size, sizeof(char));
                if (ret[k] == NULL) {
                    goto fail;
                }
                strncpy(ret[k], _lxml->el[i], el_size - 1);
                k++;
            }
        }

        else if ((_lxml->tp[i] == XML_ELEM) && (_lxml->rl[i] == j) &&
                 (element_name[j] != NULL)) {
            if (strcmp(_lxml->el[i], element_name[j]) == 0) {
                j++;
                matched = 1;
                continue;
            }
        }

        if (matched == 1) {
            if (((_lxml->tp[i] == XML_ATTR) && (j > _lxml->rl[i] + 1)) ||
                    ((_lxml->tp[i] == XML_ELEM) && (j > _lxml->rl[i]))) {
                j = 0;
                matched = 0;
                if (element_name == NULL) {
                    ready = 1;
                } else {
                    ready = 0;
                }
            }
        }
    }

    return (ret);

fail:
    i = 0;
    if (ret) {
        while (ret[i]) {
            free(ret[i++]);
        }
        free(ret);
    }
    return (NULL);
}

/* Get one value for a specific element */
char *OS_GetOneContentforElement(OS_XML *_lxml, const char **element_name)
{
    int i = 1;
    char *uniqret = NULL;
    char **ret = NULL;

    _lxml->fol = 0;
    ret = _GetElementContent(_lxml, element_name, NULL);
    if (ret == NULL) {
        return (NULL);
    }

    if (ret[0] != NULL) {
        uniqret = ret[0];
    }

    /* Free memory */
    while (ret[i]) {
        free(ret[i]);
        ret[i] = NULL;
        i++;
    }
    free(ret);

    return (uniqret);
}

/* Get all values for a specific element */
char **OS_GetElementContent(OS_XML *_lxml, const char **element_name)
{
    _lxml->fol = 0;
    return (_GetElementContent(_lxml, element_name, NULL));
}

/* Get the contents for a specific element
 * Use element_name = NULL to start the state
 */
char **OS_GetContents(OS_XML *_lxml, const char **element_name)
{
    if (element_name == NULL) {
        _lxml->fol = -1;
        return (NULL);
    }
    return (_GetElementContent(_lxml, element_name, NULL));
}

/* Get one value for a specific attribute */
char *OS_GetAttributeContent(OS_XML *_lxml, const char **element_name,
                             const char *attribute_name)
{
    char *uniqret = NULL;
    char **ret = NULL;

    _lxml->fol = 0;

    ret = _GetElementContent(_lxml, element_name, attribute_name);
    if (ret == NULL) {
        return (NULL);
    }
    if (ret[0] != NULL) {
        uniqret = ret[0];
    }

    int i = 1;
    while (ret[i] != NULL) {
        free(ret[i++]);
    }
    free(ret);

    return (uniqret);
}

/* Get the values for an element or attribute */
static char **_GetElementContent(OS_XML *_lxml, const char **element_name, const char *attr)
{
    int i = 0;
    unsigned int j = 0, k = 0, l = 0, matched = 0;
    char **ret = NULL;
    char **ret_tmp;

    if (_lxml->fol >= 0 && (unsigned int)_lxml->fol == _lxml->cur) {
        _lxml->fol = 0;
        return (NULL);
    }

    if (_lxml->fol > 0) {
        for (i = _lxml->fol; i >= 0; i--) {
            _lxml->fol = i;
            if (_lxml->rl[i] == 0) {
                break;
            }
        }
        i = _lxml->fol;
    } else {
        i = 0;
    }

    /* Loop over all nodes */
    for (j = 0, l = (unsigned int)i; l < _lxml->cur; l++) {
        if (element_name[j] == NULL) {
            if (matched != 1) {
                break;
            }
        }

        /* Set maximum depth of 16 */
        if (j > 16) {
            goto fail;
        }

        /* If the type is not an element and the relation doesn't match,
         * keep going
         */
        if ((_lxml->tp[l] != XML_ELEM) || (_lxml->rl[l] != j)) {
            /* If the node relation is higher than the current xml
             * node, zero the position and look at it again (i--).
             */
            if (j > _lxml->rl[l]) {
                j = 0;
                matched = 0;
                l--;
            } else {
                continue;
            }
        }

        /* If the element name matches what we are looking for */
        else if (element_name[j] != NULL && strcmp(_lxml->el[l], element_name[j]) == 0) {
            j++;
            matched = 1;

            /* Get content if we are at the end of the array */
            if (element_name[j] == NULL) {
                /* If we have an attribute to match */
                if (attr != NULL) {
                    unsigned int m = 0;
                    for (m = l + 1; m < _lxml->cur; m++) {
                        if (_lxml->tp[m] == XML_ELEM) {
                            break;
                        }

                        if (strcmp(attr, _lxml->el[m]) == 0) {
                            l = m;
                            break;
                        }
                    }
                }

                if (_lxml->ct[l] != NULL) {
                    /* Increase the size of the array */
                    ret_tmp = (char **) realloc(ret, (k + 2) * sizeof(char *));
                    if (ret_tmp == NULL) {
                        goto fail;
                    }
                    ret = ret_tmp;

                    /* Add new entry */
                    ret[k] = strdup(_lxml->ct[l]);
                    ret[k + 1] = NULL;
                    if (ret[k] == NULL) {
                        goto fail;
                    }

                    matched = 1;
                    k++;

                    if (attr != NULL) {
                        break;
                    }

                    else if (_lxml->fol != 0) {
                        _lxml->fol = (int) l + 1;
                        break;
                    }
                }

                /* Set new array pointer */
                if ((l < _lxml->cur - 1) && (_lxml->tp[l + 1] == XML_ELEM)) {
                    j = _lxml->rl[l + 1];
                }
            }
            continue;
        }

        if (j > _lxml->rl[l]) {
            j = 0;
            matched = 0;
        }
    }

    return (ret);

fail:
    i = 0;
    if (ret) {
        while (ret[i]) {
            free(ret[i++]);
        }
        free(ret);
    }
    return (NULL);
}

