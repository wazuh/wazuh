#ifndef _OP_BUILDER_HELPER_MAP_H
#define _OP_BUILDER_HELPER_MAP_H

#include <any>

#include <baseTypes.hpp>
#include <defs/idefinitions.hpp>
#include <schemf/ischema.hpp>

#include "expression.hpp"
#include <utils/stringUtils.hpp>
#include "registry.hpp"
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
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition i.e : `<field>: +upcase/<str>|$<ref>`
 * @param definitions handler with definitions
 * @return base::Expression The lifter with the `uppercase` transformation.
 * @throw std::runtime_error if the parameter is not a string.
 */
base::Expression opBuilderHelperStringUP(const std::string& targetField,
                                         const std::string& rawName,
                                         const std::vector<std::string>& rawParameters,
                                         std::shared_ptr<defs::IDefinitions> definitions);

/**
 * @brief Transforms a string to lowercase and append or remplace it in the event `e`
 *
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition i.e : `<field>: +downcase/<str>|$<ref>`
 * @param definitions handler with definitions
 * @return base::Expression The lifter with the `lowercase` transformation.
 * @throw std::runtime_error if the parameter is not a string.
 */
base::Expression opBuilderHelperStringLO(const std::string& targetField,
                                         const std::string& rawName,
                                         const std::vector<std::string>& rawParameters,
                                         std::shared_ptr<defs::IDefinitions> definitions);

/**
 * @brief Transforms a string, trim it and append or remplace it in the event `e`
 *
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * i.e : `<field>: +trim/[begin | end | both]/char`
 * @param definitions handler with definitions
 * @return base::Expression The lifter with the `trim` transformation.
 * @throw std::runtime_error if the parameter is not a string.
 */
base::Expression opBuilderHelperStringTrim(const std::string& targetField,
                                           const std::string& rawName,
                                           const std::vector<std::string>& rawParameters,
                                           std::shared_ptr<defs::IDefinitions> definitions);

/**
 * @brief Transform a list of arguments into a single strim with all of them concatenated
 *
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * i.e : '<field>: +concat/<stringA>|$<referenceA>/<stringB>|$<referenceB>/...'
 * @param definitions handler with definitions
 * @return base::Expression The lifter with the `concat` transformation.
 */
base::Expression opBuilderHelperStringConcat(const std::string& targetField,
                                             const std::string& rawName,
                                             const std::vector<std::string>& rawParameters,
                                             std::shared_ptr<defs::IDefinitions> definitions);

/**
 * @brief Transforms an array of strings into a single string field result of concatenate
 * them with a separator between (not at the start or the end).
 * i.e: '<field>: +join/$<array_reference1>/<separator>'
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * @param definitions handler with definitions
 * @throw std::runtime_error if the parameter is not a reference or if theres no
 * Value argument for the separator.
 * @return base::Expression
 */
base::Expression opBuilderHelperStringFromArray(const std::string& targetField,
                                                const std::string& rawName,
                                                const std::vector<std::string>& rawParameters,
                                                std::shared_ptr<defs::IDefinitions> definitions);

/**
 * @brief Transforms a string of hexa digits into an ASCII string
 * i.e: 'targetField: +decode_base16/48656C6C6F20776F726C6421' then 'targetField' would be
 * 'Hello world!'
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * @param definitions handler with definitions
 * @throw std::runtime_error if the parameter is not a reference
 * @return base::Expression
 */
base::Expression opBuilderHelperStringFromHexa(const std::string& targetField,
                                               const std::string& rawName,
                                               const std::vector<std::string>& rawParameters,
                                               std::shared_ptr<defs::IDefinitions> definitions);

/**
 * @brief Transforms a string of hexadecimal digits into a number
 * i.e: 'targetField: +hex_to_number/0x1234' then 'targetField' would be 4660
 * Fail if the string is not a valid hexadecimal number or the reference is not found.
 *
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * @param definitions handler with definitions
 * @return base::Expression
 *
 * @throw std::runtime_error if the parameter is not a reference, or more than one
 * parameter is provided
 */
base::Expression opBuilderHelperHexToNumber(const std::string& targetField,
                                            const std::string& rawName,
                                            const std::vector<std::string>& rawParameters,
                                            std::shared_ptr<defs::IDefinitions> definitions);

/**
 * @brief Transforms a string by replacing, if exists, every ocurrence of a substring by a
 * new one.
 *
 * i.e:
 * Original String: 'String with values: extras, expert, ex, flexible, exexes'
 * Substring to replace: 'ex'
 * New substring: 'dummy'
 * Result:'String with values: dummytras, dummypert, dummy, fldummyible, dummydummyes'
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * @param definitions handler with definitions
 * @throw std::runtime_error if the first parameter is empty
 * @return base::Expression
 */
base::Expression opBuilderHelperStringReplace(const std::string& targetField,
                                              const std::string& rawName,
                                              const std::vector<std::string>& rawParameters,
                                              std::shared_ptr<defs::IDefinitions> definitions);

//*************************************************
//*           Int tranform                        *
//*************************************************

/**
 * @brief Transforms an integer. Stores the result of a mathematical operation
 * of a single or a set of values or references into the target field.
 *
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * i.e : `<field>: +int_calculate/[sum|sub|mul|div]/[value1|$<ref1>]/.../[valueN|$<refN>]`
 * @param definitions handler with definitions
 * @return base::Expression The lifter with the `mathematical operation` transformation.
 * @throw std::runtime_error if the parameter is not a integer.
 */
base::Expression opBuilderHelperIntCalc(const std::string& targetField,
                                        const std::string& rawName,
                                        const std::vector<std::string>& rawParameters,
                                        std::shared_ptr<defs::IDefinitions> definitions);

//*************************************************
//*             JSON tranform                     *
//*************************************************

// <field>: +delete/
/**
 * @brief Delete a field of the json event
 *
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * i.e : '<field>: +delete
 * @param definitions handler with definitions
 * @return base::Expression The lifter with the `delete` transformation.
 */
base::Expression opBuilderHelperDeleteField(const std::string& targetField,
                                            const std::string& rawName,
                                            const std::vector<std::string>& rawParameters,
                                            std::shared_ptr<defs::IDefinitions> definitions);

/**
 * @brief Renames a field of the json event
 *
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * i.e : '<field>: +rename/$<sourceField>
 * @param definitions handler with definitions
 * @return base::Expression The lifter with the `rename` transformation.
 */
base::Expression opBuilderHelperRenameField(const std::string& targetField,
                                            const std::string& rawName,
                                            const std::vector<std::string>& rawParameters,
                                            std::shared_ptr<defs::IDefinitions> definitions);

/**
 * @brief Merge two arrays or objects.
 * Accepts one reference parameter. Fail cases:
 * - If target or source not exists
 * - If source and target, are not the same type
 * - If source or target are not arrays or objects
 *
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * @param definitions handler with definitions
 * @return base::Expression The lifter with the `merge` transformation.
 *
 * @throw std::runtime_error if the parameters size is not 1 or is not a reference.
 */
base::Expression opBuilderHelperMerge(const std::string& targetField,
                                      const std::string& rawName,
                                      const std::vector<std::string>& rawParameters,
                                      std::shared_ptr<defs::IDefinitions> definitions);

/**
 * @brief Merge recursively two arrays or two objects.
 * Accepts one reference parameter. Fail cases:
 * - If target or source not exists
 * - If source and target, are not the same type
 * - If source or target are not arrays or objects
 *
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * @param definitions handler with definitions
 * @return base::Expression The lifter with the `merge` transformation.
 *
 * @throw std::runtime_error if the parameters size is not 1 or is not a reference.
 */

base::Expression opBuilderHelperMergeRecursively(const std::string& targetField,
                                                 const std::string& rawName,
                                                 const std::vector<std::string>& rawParameters,
                                                 std::shared_ptr<defs::IDefinitions> definitions);

//*************************************************
//*           Regex tranform                      *
//*************************************************

/**
 * @brief Builds regex extract operation.
 * Maps into an auxiliary field the part of the field value that matches a regexp
 *
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * @param definitions handler with definitions
 * @return base::Expression The lifter with the `regex extract` transformation.
 * @throw std::runtime_error if the parameter is the regex is invalid.
 */
base::Expression opBuilderHelperRegexExtract(const std::string& targetField,
                                             const std::string& rawName,
                                             const std::vector<std::string>& rawParameters,
                                             std::shared_ptr<defs::IDefinitions> definitions);

//*************************************************
//*           Array tranform                      *
//*************************************************

/**
 * @brief Append string to array field.
 * Accepts parameters with literals or references. If reference not exists or is not an
 * string it will fail.
 *
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * @param definitions handler with definitions
 * @return base::Expression The lifter with the `append string to array` transformation.
 * @throw std::runtime_error if the parameters are empty.
 */
base::Expression opBuilderHelperAppend(const std::string& targetField,
                                       const std::string& rawName,
                                       const std::vector<std::string>& rawParameters,
                                       std::shared_ptr<defs::IDefinitions> definitions);

base::Expression opBuilderHelperAppendSplitString(const std::string& targetField,
                                                  const std::string& rawName,
                                                  const std::vector<std::string>& rawParameters,
                                                  std::shared_ptr<defs::IDefinitions> definitions);

//*************************************************
//*              IP tranform                      *
//*************************************************
/**
 * @brief Get the Internet Protocol version of an IP address.
 *
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * @param definitions handler with definitions
 * @return base::Expression The lifter with the `ip version` transformation.
 */
base::Expression opBuilderHelperIPVersionFromIPStr(const std::string& targetField,
                                                   const std::string& rawName,
                                                   const std::vector<std::string>& rawParameters,
                                                   std::shared_ptr<defs::IDefinitions> definitions);

//*************************************************
//*              Time tranform                    *
//*************************************************
/**
 * @brief Get unix epoch time in seconds from system clock
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * @param definitions handler with definitions
 * @throw std::runtime_error if the parameter is not a reference
 * @return base::Expression
 */
base::Expression opBuilderHelperEpochTimeFromSystem(const std::string& targetField,
                                                    const std::string& rawName,
                                                    const std::vector<std::string>& rawParameters,
                                                    std::shared_ptr<defs::IDefinitions> definitions);

//*************************************************
//*              Checksum and hash                *
//*************************************************

/**
 * @brief Builds helper SHA1 hash calculated from a strings or a reference.
 * <field>: +sha1/<string1>|$<string_reference1>
 *
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition.
 * @param definitions handler with definitions
 * @return base::Expression The Lifter with the SHA1 hash.
 * @throw std::runtime_error if the parameter size is not one.
 */
base::Expression opBuilderHelperHashSHA1(const std::string& targetField,
                                         const std::string& rawName,
                                         const std::vector<std::string>& rawParameters,
                                         std::shared_ptr<defs::IDefinitions> definitions);

//*************************************************
//*                  Definition                   *
//*************************************************

/**
 * @brief Create 'get_value' helper function that maps target field value with the content of the some key in the
 * definition object, where the key is specified with a reference to another field.
 * <field>: +get_value/$<definition_object>|$<object_reference>/$<key>
 *
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition.
 * @param definitions handler with definitions
 * @param schema schema to validate fields
 * @return base::Expression
 */
base::Expression opBuilderHelperGetValue(const std::string& targetField,
                                              const std::string& rawName,
                                              const std::vector<std::string>& rawParameters,
                                              std::shared_ptr<defs::IDefinitions> definitions,
                                              std::shared_ptr<schemf::ISchema> schema);

/**
 * @brief Get the 'get_value' function helper builder
 *
 * @param schema schema to validate fields
 * @return builder
 */
HelperBuilder getOpBuilderHelperGetValue(std::shared_ptr<schemf::ISchema> schema);


/**
 * @brief Create 'merge_value' helper function that merge target field value with the content of the some key in the
 * definition object, where the key is specified with a reference to another field.
 * <field>: +merge_value/$<definition_object>|$<object_reference>/$<key>
 *
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition.
 * @param definitions handler with definitions
 * @param schema schema to validate fields
 * @return base::Expression
 */
base::Expression opBuilderHelperMergeValue(const std::string& targetField,
                                              const std::string& rawName,
                                              const std::vector<std::string>& rawParameters,
                                              std::shared_ptr<defs::IDefinitions> definitions,
                                              std::shared_ptr<schemf::ISchema> schema);

/**
 * @brief Get the 'merge_value' function helper builder
 *
 * @param schema schema to validate fields
 * @return builder
 */
HelperBuilder getOpBuilderHelperMergeValue(std::shared_ptr<schemf::ISchema> schema);

} // namespace builder::internals::builders

#endif // _OP_BUILDER_HELPER_MAP_H
