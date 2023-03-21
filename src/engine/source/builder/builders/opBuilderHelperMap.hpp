/* Copyright (C) 2015-2022, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _OP_BUILDER_HELPER_MAP_H
#define _OP_BUILDER_HELPER_MAP_H

#include <any>

#include <baseTypes.hpp>

#include "expression.hpp"
#include <utils/stringUtils.hpp>
/*
 * The helper Map (Transformation), builds a lifter that will chain rxcpp map operation
 * Rxcpp transform expects a function that returns event.
 */

namespace builder::internals::builders
{

//*************************************************
//*           String tranform                     *
//*************************************************

/**
 * @brief Transforms a string to uppercase and append or remplace it in the event `e`
 *
 * @param definition The transformation definition. i.e : `<field>: +upcase/<str>|$<ref>`
 * @return base::Expression The lifter with the `uppercase` transformation.
 * @throw std::runtime_error if the parameter is not a string.
 */
base::Expression opBuilderHelperStringUP(const std::any& definition);

/**
 * @brief Transforms a string to lowercase and append or remplace it in the event `e`
 *
 * @param definition The transformation definition. i.e : `<field>: +downcase/<str>|$<ref>`
 * @return base::Expression The lifter with the `lowercase` transformation.
 * @throw std::runtime_error if the parameter is not a string.
 */
base::Expression opBuilderHelperStringLO(const std::any& definition);

/**
 * @brief Transforms a string, trim it and append or remplace it in the event `e`
 *
 * @param definition The transformation definition.
 * i.e : `<field>: +trim/[begin | end | both]/char`
 * @return base::Expression The lifter with the `trim` transformation.
 * @throw std::runtime_error if the parameter is not a string.
 */
base::Expression opBuilderHelperStringTrim(const std::any& definition);

/**
 * @brief Transform a list of arguments into a single strim with all of them concatenated
 *
 * @param def The transformation definition.
 * i.e : '<field>: +concat/<stringA>|$<referenceA>/<stringB>|$<referenceB>/...'
 * @return base::Expression The lifter with the `concat` transformation.
 */
base::Expression opBuilderHelperStringConcat(const std::any& definition);

/**
 * @brief Transforms an array of strings into a single string field result of concatenate
 * them with a separator between (not at the start or the end).
 * i.e: '<field>: +join/$<array_reference1>/<separator>'
 * @param definition The transformation definition.
 * @throw std::runtime_error if the parameter is not a reference or if theres no
 * Value argument for the separator.
 * @return base::Expression
 */
base::Expression opBuilderHelperStringFromArray(const std::any& definition);

/**
 * @brief Transforms a string of hexa digits into an ASCII string
 * i.e: 'targetField: +decode_base16/48656C6C6F20776F726C6421' then 'targetField' would be
 * 'Hello world!'
 * @param definition The transformation definition.
 * @throw std::runtime_error if the parameter is not a reference
 * @return base::Expression
 */
base::Expression opBuilderHelperStringFromHexa(const std::any& definition);

/**
 * @brief Transforms a string of hexadecimal digits into a number
 * i.e: 'targetField: +hex_to_number/0x1234' then 'targetField' would be 4660
 * Fail if the string is not a valid hexadecimal number or the reference is not found.
 *
 * @param definition The transformation definition.
 * @return base::Expression
 *
 * @throw std::runtime_error if the parameter is not a reference, or more than one
 * parameter is provided
 */
base::Expression opBuilderHelperHexToNumber(const std::any& definition);

/**
 * @brief Transforms a string by replacing, if exists, every ocurrence of a substring by a
 * new one.
 *
 * i.e:
 * Original String: 'String with values: extras, expert, ex, flexible, exexes'
 * Substring to replace: 'ex'
 * New substring: 'dummy'
 * Result:'String with values: dummytras, dummypert, dummy, fldummyible, dummydummyes'
 * @param definition The transformation definition.
 * @throw std::runtime_error if the first parameter is empty
 * @return base::Expression
 */
base::Expression opBuilderHelperStringReplace(const std::any& definition);

//*************************************************
//*           Int tranform                        *
//*************************************************

/**
 * @brief Transforms an integer. Stores the result of a mathematical operation
 * of a single or a set of values or references into the target field.
 *
 * @param definition The transformation definition.
 * i.e : `<field>: +int_calculate/[sum|sub|mul|div]/[value1|$<ref1>]/.../[valueN|$<refN>]`
 * @return base::Expression The lifter with the `mathematical operation` transformation.
 * @throw std::runtime_error if the parameter is not a integer.
 */
base::Expression opBuilderHelperIntCalc(const std::any& definition);

//*************************************************
//*             JSON tranform                     *
//*************************************************

// <field>: +delete/
/**
 * @brief Delete a field of the json event
 *
 * @param def The transformation definition.
 * i.e : '<field>: +delete
 * @return base::Expression The lifter with the `delete` transformation.
 */
base::Expression opBuilderHelperDeleteField(const std::any& definition);

/**
 * @brief Renames a field of the json event
 *
 * @param def The transformation definition.
 * i.e : '<field>: +rename/$<sourceField>
 * @return base::Expression The lifter with the `rename` transformation.
 */
base::Expression opBuilderHelperRenameField(const std::any& definition);


/**
 * @brief Merge two arrays or objects.
 * Accepts one reference parameter. Fail cases:
 * - If target or source not exists
 * - If source and target, are not the same type
 * - If source or target are not arrays or objects
 *
 * @param definition Definition of the operation to be built
 * @return base::Expression The lifter with the `merge` transformation.
 *
 * @throw std::runtime_error if the parameters size is not 1 or is not a reference.
 */
base::Expression opBuilderHelperMerge(const std::any& definition);

/**
 * @brief Merge recursively two arrays or two objects.
 * Accepts one reference parameter. Fail cases:
 * - If target or source not exists
 * - If source and target, are not the same type
 * - If source or target are not arrays or objects
 *
 * @param definition Definition of the operation to be built
 * @return base::Expression The lifter with the `merge` transformation.
 *
 * @throw std::runtime_error if the parameters size is not 1 or is not a reference.
 */

base::Expression opBuilderHelperMergeRecursively(const std::any& definition);

//*************************************************
//*           Regex tranform                      *
//*************************************************

/**
 * @brief Builds regex extract operation.
 * Maps into an auxiliary field the part of the field value that matches a regexp
 *
 * @param definition Definition of the operation to be built
 * @return base::Expression The lifter with the `regex extract` transformation.
 * @throw std::runtime_error if the parameter is the regex is invalid.
 */
base::Expression opBuilderHelperRegexExtract(const std::any& definition);

//*************************************************
//*           Array tranform                      *
//*************************************************

/**
 * @brief Append string to array field.
 * Accepts parameters with literals or references. If reference not exists or is not an
 * string it will fail.
 *
 * @param definition Definition of the operation to be built
 * @return base::Expression The lifter with the `append string to array` transformation.
 * @throw std::runtime_error if the parameters are empty.
 */
base::Expression opBuilderHelperAppend(const std::any& definition);

base::Expression opBuilderHelperAppendSplitString(const std::any& definition);

//*************************************************
//*              IP tranform                      *
//*************************************************
/**
 * @brief Get the Internet Protocol version of an IP address.
 *
 * @param definition The transformation definition.
 * @return base::Expression The lifter with the `ip version` transformation.
 */
base::Expression opBuilderHelperIPVersionFromIPStr(const std::any& definition);

//*************************************************
//*              Time tranform                    *
//*************************************************
/**
 * @brief Get unix epoch time in seconds from system clock
 * @param definition The transformation definition.
 * @throw std::runtime_error if the parameter is not a reference
 * @return base::Expression
 */
base::Expression opBuilderHelperEpochTimeFromSystem(const std::any& definition);

//*************************************************
//*              Checksum and hash                *
//*************************************************

/**
 * @brief Builds helper SHA1 hash calculated from a strings or a reference.
 * <field>: +sha1/<string1>|$<string_reference1>
 *
 * @param definition Definition of the operation to be built.
 * @return base::Expression The Lifter with the SHA1 hash.
 * @throw std::runtime_error if the parameter size is not one.
 */
base::Expression opBuilderHelperHashSHA1(const std::any& definition);

} // namespace builder::internals::builders

#endif // _OP_BUILDER_HELPER_MAP_H
