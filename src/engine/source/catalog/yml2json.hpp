#ifndef __YML2JSON_H__
#define __YML2JSON_H__


#include "yaml-cpp/yaml.h"
#include "nlohmann/json.hpp"

#include <fstream>

#if __has_cpp_attribute(nodiscard)
#define TOJSON_NODISCARD [[nodiscard]]
#else
#define TOJSON_NODISCARD
#endif



namespace tojson {
namespace detail {


inline nlohmann::ordered_json parse_scalar(const YAML::Node &node) {
	int i;
	double d;
	bool b;
	std::string s;

	if (YAML::convert<int>::decode(node, i)) return i;
	if (YAML::convert<double>::decode(node, d)) return d;
	if (YAML::convert<bool>::decode(node, b)) return b;
	if (YAML::convert<std::string>::decode(node, s)) return s;

	return nullptr;
}

/// \todo refactor and pass nlohmann::ordered_json down by reference instead of returning it
inline nlohmann::ordered_json yaml2json(const YAML::Node &root) {
	nlohmann::ordered_json j{};

	switch (root.Type()) {
	case YAML::NodeType::Null: break;
	case YAML::NodeType::Scalar: return parse_scalar(root);
	case YAML::NodeType::Sequence:
		for (auto &&node : root)
			j.emplace_back(yaml2json(node));
		break;
	case YAML::NodeType::Map:
		for (auto &&it : root)
			j[it.first.as<std::string>()] = yaml2json(it.second);
		break;
	default: break;
	}
	return j;
}

/// \todo handle @text entries better
inline void toyaml(const nlohmann::ordered_json &j, YAML::Emitter &e) {
	for (auto it = j.begin(); it != j.end(); ++it) {
		if (it->is_object()) {
			e << YAML::Key << it.key() << YAML::Value << YAML::BeginMap;
			toyaml(*it, e);
			e << YAML::EndMap;
		} else if (it->is_array()) {
			e << YAML::Key << it.key() << YAML::Value << YAML::BeginSeq;
			toyaml(it.value(), e);
			e << YAML::EndSeq;
		} else {
			if (it.key() == "@text") {
				e << YAML::Value << it.value().get<std::string>();
			} else {
				e << YAML::Key << it.key() << YAML::Value << it.value().get<std::string>();
			}
		}
	}
}


inline std::string repr(const nlohmann::ordered_json &j) {
	if (j.is_number()) return std::to_string(j.get<int>());
	if (j.is_boolean()) return j.get<bool>() ? "true" : "false";
	if (j.is_number_float()) return std::to_string(j.get<double>());
	if (j.is_string()) return j.get<std::string>();
	std::runtime_error("invalid type");
	return "";
}

/// \brief Convert YAML string to JSON.
TOJSON_NODISCARD inline nlohmann::ordered_json yaml2json(const std::string &str) {
	YAML::Node root = YAML::Load(str);
	return detail::yaml2json(root);
}

/// \brief Load a YAML file to JSON.
TOJSON_NODISCARD inline nlohmann::ordered_json loadyaml(const std::string &filepath) {
	YAML::Node root = YAML::LoadFile(filepath);
	return detail::yaml2json(root);
}

} // end namespace detail
namespace emitters {

/// \brief Generate string representation of json as an YAML document.
TOJSON_NODISCARD inline std::string toyaml(const nlohmann::ordered_json &j) {
	YAML::Emitter e;
	e << YAML::BeginDoc;
	if (j.is_object()) {
		e << YAML::BeginMap;
		detail::toyaml(j, e);
		e << YAML::EndMap;
	} else if (j.is_array()) {
		e << YAML::BeginSeq;
		detail::toyaml(j, e);
		e << YAML::EndSeq;
	}
	e << YAML::EndDoc;
	return e.c_str();
}


}  // namespace emitters
}  // namespace tojson

#endif // __YML2JSON_H__
