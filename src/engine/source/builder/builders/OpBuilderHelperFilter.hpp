/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _OP_BUILDER_HELPER_FILTER_H
#define _OP_BUILDER_HELPER_FILTER_H

#include "builderTypes.hpp"

/*
 * The helper filter, builds a lifter that will chain rxcpp filter operation
 * Rxcpp filter expects a function that returns bool.
 */

namespace builder::internals::builders
{

/**
 * @brief Create `exists` helper function that filters events that contains specified field.
 *
 * The filter checks if a field exists in the JSON event `e`.
 * For example: if def = `{wazuh: +exists}` only events containing `wazuh` field
 * will continue on the rxcpp pipeline.
 * @param def The filter definition. i.e : `{wazuh: +exists}`
 * @return types::Lifter The lifter with the `exists` filter.
 */
types::Lifter opBuilderHelperExists(const types::DocumentValue & def);

/**
 * @brief Create `not_exists` helper function that filters events that not contains specified field.
 *
 * The filter checks if a field not exists in the JSON event `e`.
 * For example: if def = `{wazuh: +not_exists}` only events not containing `wazuh`
 * field will continue on the rxcpp pipeline.
 * @param def The filter definition. i.e : `{wazuh: +exists}`
 * @return types::Lifter The lifter with the `exists` filter.
 */
types::Lifter opBuilderHelperNotExists(const types::DocumentValue & def);

/**
 * @brief Builds helper integer equal operation.
 * Checks that the field is equal to an integer or another numeric field
 *
 * @param def Definition of the operation to be built
 * @return types::Lifter
 */
types::Lifter opBuilderHelperIntEqual(const types::DocumentValue & def);

// TODO Doc
inline bool opBuilderHelperAUXStringManipulation(const std::string  key, char op, types::Event& e,
                                                 std::optional<std::string> refExpStr,
                                                 std::optional<std::string> expectedStr);

/**
 * @brief Create `s_eq` helper function that filters events with a string
 * field equals to a value.
 *
 * The filter checks if a field in the JSON event `wazuh` is equal to a value.
 * @param def The filter definition. i.e : `{wazuh: +s_eq/value}`
 * @return types::Lifter The lifter with the `s_eq` filter.
 * @throw std::runtime_error if the parameter is not a string.
 */
types::Lifter opBuilderHelperString_eq(const types::DocumentValue & def);
} // namespace builder::internals::builders

#endif // _OP_BUILDER_HELPER_FILTER_H
