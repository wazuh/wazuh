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
 */
types::Lifter opBuilderHelperStringUP(const types::DocumentValue & def);

/**
 * @brief Transforms a string to lowercase and append or remplace it in the event `e`
 *
 * @param def The transformation definition. i.e : `<field>: +s_lo/<str>|$<ref>`
 * @return types::Lifter The lifter with the `lowercase` transformation.
 */
types::Lifter opBuilderHelperStringLO(const types::DocumentValue & def);

/**
 * @brief Transforms a string, trim it and append or remplace it in the event `e`
 *
 * @param def The transformation definition. i.e : `<field>: +s_trim/[begin | end | both]/char`
 * @return types::Lifter The lifter with the `trim` transformation.
 */
types::Lifter opBuilderHelperStringTrim(const types::DocumentValue & def);

} // namespace builder::internals::builders

#endif // _OP_BUILDER_HELPER_MAP_H
