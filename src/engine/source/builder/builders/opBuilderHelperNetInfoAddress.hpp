/* Copyright (C) 2015-2022, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _OP_BUILDER_HELPER_NETINFO_ADDRES_H
#define _OP_BUILDER_HELPER_NETINFO_ADDRES_H

#include <any>

#include <baseTypes.hpp>

#include "expression.hpp"

/*
 * The helper Map (Transformation), builds a lifter that will chain rxcpp map operation
 * Rxcpp transform expects a function that returns event.
 */

namespace builder::internals::builders
{

/**
 * @brief 
 * 
 * @param definition 
 * @return base::Expression 
 */
// field: +netInfoAddress/<1_if_IPv6>|<ref_if_IPv6>
base::Expression opBuilderHelperNetInfoAddres(const std::any& definition);

} // namespace builder::internals::builders

#endif // _OP_BUILDER_HELPER_NETINFO_ADDRES_H
