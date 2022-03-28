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

#include "builderTypes.hpp"

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
 * @param def The transformation definition. i.e : `<field>: +s_up/<str>|$<ref>`
 * @return types::Lifter The lifter with the `uppercase` transformation.
 * @throw std::runtime_error if the parameter is not a string.
 */
types::Lifter opBuilderHelperStringUP(const types::DocumentValue & def, types::TracerFn tr);

/**
 * @brief Transforms a string to lowercase and append or remplace it in the event `e`
 *
 * @param def The transformation definition. i.e : `<field>: +s_lo/<str>|$<ref>`
 * @return types::Lifter The lifter with the `lowercase` transformation.
 * @throw std::runtime_error if the parameter is not a string.
 */
types::Lifter opBuilderHelperStringLO(const types::DocumentValue & def, types::TracerFn tr);

/**
 * @brief Transforms a string, trim it and append or remplace it in the event `e`
 *
 * @param def The transformation definition.
 * i.e : `<field>: +s_trim/[begin | end | both]/char`
 * @return types::Lifter The lifter with the `trim` transformation.
 * @throw std::runtime_error if the parameter is not a string.
 */
types::Lifter opBuilderHelperStringTrim(const types::DocumentValue & def, types::TracerFn tr);

//*************************************************
//*           Int tranform                        *
//*************************************************

/**
 * @brief Transforms an integer. Performs a mathematical operation on an event field.
 *
 * @param def The transformation definition.
 * i.e : `<field>: +icalcm/[sum|sub|mul|div]/[value|$<ref>]`
 * @return types::Lifter The lifter with the `mathematical operation` transformation.
 * @throw std::runtime_error if the parameter is not a integer.
 */
types::Lifter opBuilderHelperIntCalc(const types::DocumentValue & def, types::TracerFn tr);

//*************************************************
//*           Regex tranform                      *
//*************************************************

/**
 * @brief Builds regex extract operation.
 * Maps into an auxiliary field the part of the field value that matches a regexp
 *
 * @param def Definition of the operation to be built
 * @return types::Lifter The lifter with the `regex extract` transformation.
 * @throw std::runtime_error if the parameter is the regex is invalid.
 */
types::Lifter opBuilderHelperRegexExtract(const types::DocumentValue & def, types::TracerFn tr);

} // namespace builder::internals::builders

#endif // _OP_BUILDER_HELPER_MAP_H
