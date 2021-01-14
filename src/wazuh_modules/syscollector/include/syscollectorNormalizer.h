/*
 * Wazuh SysCollector
 * Copyright (C) 2015-2021, Wazuh Inc.
 * January 12, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#ifndef _SYSCOLLECTOR_NORMALIZER_H
#define _SYSCOLLECTOR_NORMALIZER_H
#include <json.hpp>
#include <string>
#include <map>

class SysNormalizer
{
public:
	SysNormalizer(const std::string& configFile,
				  const std::string& target);
	~SysNormalizer() = default;
	nlohmann::json normalize(const std::string& type,
							 const nlohmann::json& data) const;
	nlohmann::json removeExcluded(const std::string& type,
				   				  const nlohmann::json& data) const;
private:
	struct ExclusionItem
	{
		std::string fieldName;
		std::string pattern;
	};
	enum DictionaryAction
	{
		ADD_VALUE,
		REPLACE_VALUE,
	};
	struct DictionaryItem
	{
		std::string srcFieldName;
		std::string destFieldName;
		std::string pattern;
		std::string value;
		DictionaryAction action;
	};
	using DataType = std::string;
	using Dictionary = std::vector<DictionaryItem>;
	using Exclusions = std::vector<ExclusionItem>;

	static std::map<DataType, Exclusions> getTypeExclusions(const std::string& configFile,
														    const std::string& target);
	static std::map<DataType, Dictionary> getTypeDictionary(const std::string& configFile,
														    const std::string& target);
	const std::map<DataType, Exclusions> m_typeExclusions;
	const std::map<DataType, Dictionary> m_typeDictionary;
};


#endif //_SYSCOLLECTOR_NORMALIZER_H