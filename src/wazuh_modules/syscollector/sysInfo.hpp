/*
 * Wazuh RSYNC
 * Copyright (C) 2015-2020, Wazuh Inc.
 * October 8, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#ifndef _SYS_INFO_HPP
#define _SYS_INFO_HPP
#include "json.hpp"

class SysInfo
{
public:
	SysInfo() = default;
	virtual ~SysInfo() = default;
	virtual nlohmann::json hardware();
private:
};


#endif //_SYS_INFO_HPP