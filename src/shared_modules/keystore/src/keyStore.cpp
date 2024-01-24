/*
 * Wazuh keystore
 * Copyright (C) 2015, Wazuh Inc.
 * January 24, 2024.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "keyStore.hpp"
#include "rsaHelper.hpp"


void Keystore::put(const std::string& columnFamily, const std::string& key, const rocksdb::Slice& value)
{
}

void Keystore::get(const std::string& columnFamily, const std::string& key, rocksdb::PinnableSlice& value)
{
}
