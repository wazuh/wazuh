#ifndef _OP_BUILDER_HELPER_MAP_H
#define _OP_BUILDER_HELPER_MAP_H

#include <base/utils/stringUtils.hpp>

#include "builders/types.hpp"

/*
 * The helper Map (Transformation), builds a lifter that will chain rxcpp map operation
 * Rxcpp transform expects a function that returns event.
 */

namespace builder::builders
{

//*************************************************
//*           String tranform                     *
//*************************************************

/**
 * @brief Transforms a string to uppercase and append or remplace it in the event `e`
 *
 * @param opArgs Vector of operation arguments containing numeric values to be converted.
 * @param buildCtx Shared pointer to the build context used for the conversion operation.
 * @return base::Expression The lifter with the `uppercase` transformation.
 * @throw std::runtime_error if the parameter is not a string.
 */
MapOp opBuilderHelperStringUP(const std::vector<OpArg>& opArgs, const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Transforms a string to lowercase and append or remplace it in the event `e`
 *
 * @param opArgs Vector of operation arguments containing numeric values to be converted.
 * @param buildCtx Shared pointer to the build context used for the conversion operation.
 * @return base::Expression The lifter with the `lowercase` transformation.
 * @throw std::runtime_error if the parameter is not a string.
 */
MapOp opBuilderHelperStringLO(const std::vector<OpArg>& opArgs, const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Transforms a string, trim it and append or remplace it in the event `e`
 *
 * @param opArgs Vector of operation arguments containing numeric values to be converted.
 * @param buildCtx Shared pointer to the build context used for the conversion operation.
 * @return base::Expression The lifter with the `trim` transformation.
 * @throw std::runtime_error if the parameter is not a string.
 */
TransformOp opBuilderHelperStringTrim(const Reference& targetField,
                                      const std::vector<OpArg>& opArgs,
                                      const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Helper function to build a MapOp that concatenates strings from OpArgs.
 *
 * This function constructs a MapOp that concatenates strings from OpArgs, either directly
 * provided as values or retrieved from references in the event.
 *
 * @param atleastOne Flag indicating whether concatenation should occur even if some
 *                   references are not found (`true`), or concatenation should only
 *                   occur when all references are resolved (`false`).
 * @return A MapBuilder function that constructs the MapOp.
 */
MapBuilder opBuilderHelperStringConcat(bool atleastOne = false);

/**
 * @brief Transforms an array of strings into a single string field result of concatenate
 * them with a separator between (not at the start or the end).
 * i.e: '<field>: +join/$<array_reference1>/<separator>'
 * @param opArgs Vector of operation arguments containing numeric values to be converted.
 * @param buildCtx Shared pointer to the build context used for the conversion operation.
 * @throw std::runtime_error if the parameter is not a reference or if theres no
 * Value argument for the separator.
 * @return base::Expression
 */
MapOp opBuilderHelperStringFromArray(const std::vector<OpArg>& opArgs,
                                     const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Transforms a string of hexa digits into an ASCII string
 * i.e: 'targetField: +decode_base16/48656C6C6F20776F726C6421' then 'targetField' would be
 * 'Hello world!'
 * @param opArgs Vector of operation arguments containing numeric values to be converted.
 * @param buildCtx Shared pointer to the build context used for the conversion operation.
 * @throw std::runtime_error if the parameter is not a reference
 * @return base::Expression
 */
MapOp opBuilderHelperStringFromHexa(const std::vector<OpArg>& opArgs, const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Transforms a string of hexadecimal digits into a number
 * i.e: 'targetField: +hex_to_number/0x1234' then 'targetField' would be 4660
 * Fail if the string is not a valid hexadecimal number or the reference is not found.
 *
 * @param opArgs Vector of operation arguments containing numeric values to be converted.
 * @param buildCtx Shared pointer to the build context used for the conversion operation.
 * @return base::Expression
 *
 * @throw std::runtime_error if the parameter is not a reference, or more than one
 * parameter is provided
 */
MapOp opBuilderHelperHexToNumber(const std::vector<OpArg>& opArgs, const std::shared_ptr<const IBuildCtx>& buildCtx);

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
 * @param opArgs Vector of operation arguments containing numeric values to be converted.
 * @param buildCtx Shared pointer to the build context used for the conversion operation.
 * @throw std::runtime_error if the first parameter is empty
 * @return base::Expression
 */
TransformOp opBuilderHelperStringReplace(const Reference& targetField,
                                         const std::vector<OpArg>& opArgs,
                                         const std::shared_ptr<const IBuildCtx>& buildCtx);

//*************************************************
//*           Int tranform                        *
//*************************************************

/**
 * @brief Converts numbers to strings using a specified format.
 *
 * This function takes a vector of operation arguments and a shared pointer to a build context.
 * It converts numeric values present in the operation arguments to strings based on the specified format
 * and returns a MapOp representing the result.
 *
 * @param opArgs Vector of operation arguments containing numeric values to be converted.
 * @param buildCtx Shared pointer to the build context used for the conversion operation.
 *
 * @return MapOp representing the result of the conversion.
 *
 * @note The conversion format and options are determined by the implementation of the build context.
 * @throw std::runtime_error if there is an issue with the conversion process.
 */
MapOp opBuilderHelperNumberToString(const std::vector<OpArg>& opArgs, const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Transforms an number. Stores the result of a mathematical operation
 * of a single or a set of values or references into the target field.
 *
 * @param opArgs Vector of operation arguments containing numeric values to be converted.
 * @param buildCtx Shared pointer to the build context used for the conversion operation.
 * @param intCalc If true, only integers are used; if false, integers and floats.
 * @return base::Expression The lifter with the `mathematical operation` transformation.
 * @throw If parameter is not an integer when intCalc is true or if parameter is not a number when intCalc is false.
 */
MapBuilder getOpBuilderHelperCalc(bool intCalc);

//*************************************************
//*             JSON tranform                     *
//*************************************************

// <field>: +delete/
/**
 * @brief Delete a field of the json event
 *
 * @param targetField target field of the helper
 * @param opArgs Vector of operation arguments containing numeric values to be converted.
 * @param buildCtx Shared pointer to the build context used for the conversion operation.
 * @return base::Expression The lifter with the `delete` transformation.
 */
TransformOp opBuilderHelperDeleteField(const Reference& targetField,
                                       const std::vector<OpArg>& opArgs,
                                       const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Renames a field of the json event
 *
 * @param targetField target field of the helper
 * @param opArgs Vector of operation arguments containing numeric values to be converted.
 * @param buildCtx Shared pointer to the build context used for the conversion operation.
 * @return base::Expression The lifter with the `rename` transformation.
 */
TransformOp opBuilderHelperRenameField(const Reference& targetField,
                                       const std::vector<OpArg>& opArgs,
                                       const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Merge two arrays or objects.
 * Accepts one reference parameter. Fail cases:
 * - If target or source not exists
 * - If source and target, are not the same type
 * - If source or target are not arrays or objects
 *
 * @param targetField target field of the helper
 * @param opArgs Vector of operation arguments containing numeric values to be converted.
 * @param buildCtx Shared pointer to the build context used for the conversion operation.
 * @return base::Expression The lifter with the `merge` transformation.
 *
 * @throw std::runtime_error if the parameters size is not 1 or is not a reference.
 */
TransformOp opBuilderHelperMerge(const Reference& targetField,
                                 const std::vector<OpArg>& opArgs,
                                 const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Merge recursively two arrays or two objects.
 * Accepts one reference parameter. Fail cases:
 * - If target or source not exists
 * - If source and target, are not the same type
 * - If source or target are not arrays or objects
 *
 * @param targetField target field of the helper
 * @param opArgs Vector of operation arguments containing numeric values to be converted.
 * @param buildCtx Shared pointer to the build context used for the conversion operation.
 * @return base::Expression The lifter with the `merge` transformation.
 *
 * @throw std::runtime_error if the parameters size is not 1 or is not a reference.
 */

TransformOp opBuilderHelperMergeRecursively(const Reference& targetField,
                                            const std::vector<OpArg>& opArgs,
                                            const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Function that returns a builder for the operation to erase custom fields from an event.
 *
 * @param targetField target field of the helper
 * @param opArgs Vector of operation arguments containing numeric values to be converted.
 * @param buildCtx Shared pointer to the build context used for the conversion operation.
 * @return A HelperBuilder object that erases custom fields from an event.
 */
TransformOp opBuilderHelperEraseCustomFields(const Reference& targetField,
                                             const std::vector<OpArg>& opArgs,
                                             const std::shared_ptr<const IBuildCtx>& buildCtx);

//*************************************************
//*           Regex tranform                      *
//*************************************************

/**
 * @brief Builds regex extract operation.
 * Maps into an auxiliary field the part of the field value that matches a regexp
 *
 * @param opArgs Vector of operation arguments containing numeric values to be converted.
 * @param buildCtx Shared pointer to the build context used for the conversion operation.
 * @return base::Expression The lifter with the `regex extract` transformation.
 * @throw std::runtime_error if the parameter is the regex is invalid.
 */
MapOp opBuilderHelperRegexExtract(const std::vector<OpArg>& opArgs, const std::shared_ptr<const IBuildCtx>& buildCtx);

//*************************************************
//*           Array tranform                      *
//*************************************************

/**
 * @brief Get the Builder Array Append Split
 *
 * @param targetField target field of the helper
 * @param opArgs Vector of operation arguments containing numeric values to be converted.
 * @param buildCtx Shared pointer to the build context used for the conversion operation.
 * @return base::Expression
 */
TransformOp opBuilderHelperAppendSplitString(const Reference& targetField,
                                             const std::vector<OpArg>& opArgs,
                                             const std::shared_ptr<const IBuildCtx>& buildCtx);

//*************************************************
//*              IP tranform                      *
//*************************************************
/**
 * @brief Get the Internet Protocol version of an IP address.
 *
 * @param opArgs Vector of operation arguments containing numeric values to be converted.
 * @param buildCtx Shared pointer to the build context used for the conversion operation.
 * @return base::Expression The lifter with the `ip version` transformation.
 */
MapOp opBuilderHelperIPVersionFromIPStr(const std::vector<OpArg>& opArgs,
                                        const std::shared_ptr<const IBuildCtx>& buildCtx);

//*************************************************
//*              Time tranform                    *
//*************************************************
/**
 * @brief Get unix epoch time in seconds from system clock
 *
 * @param opArgs Vector of operation arguments containing numeric values to be converted.
 * @param buildCtx Shared pointer to the build context used for the conversion operation.
 * @throw std::runtime_error if the parameter is not a reference
 * @return base::Expression
 */
MapOp opBuilderHelperEpochTimeFromSystem(const std::vector<OpArg>& opArgs,
                                         const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Transform epoch time in seconds to human readable string
 *
 * @param opArgs Vector of operation arguments containing numeric values to be converted.
 * @param buildCtx Shared pointer to the build context used for the conversion operation.
 * @throw std::runtime when type of number of paramter missmatch
 * @return base::Expression
 */
MapOp opBuilderHelperDateFromEpochTime(const std::vector<OpArg>& opArgs,
                                       const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Builds an operation to generate the current date in ISO 8601 format.
 *
 * This function returns a callable operation that produces the current date
 * in the format "%Y-%m-%dT%H:%M:%SZ". The date is generated in UTC time zone.
 *
 * @param opArgs Vector of operation arguments containing numeric values to be converted.
 * @param buildCtx Shared pointer to the build context used for the conversion operation.
 * @throw std::runtime when type of number of paramter missmatch
 * @return base::Expression
 */
MapOp opBuilderHelperGetDate(const std::vector<OpArg>& opArgs, const std::shared_ptr<const IBuildCtx>& buildCtx);

//*************************************************
//*              Checksum and hash                *
//*************************************************

/**
 * @brief Builds helper SHA1 hash calculated from a strings or a reference.
 * <field>: +sha1/<string1>|$<string_reference1>
 *
 * @param opArgs Vector of operation arguments containing numeric values to be converted.
 * @param buildCtx Shared pointer to the build context used for the conversion operation.
 * @return base::Expression The Lifter with the SHA1 hash.
 * @throw std::runtime_error if the parameter size is not one.
 */
MapOp opBuilderHelperHashSHA1(const std::vector<OpArg>& opArgs, const std::shared_ptr<const IBuildCtx>& buildCtx);

//*************************************************
//*                  Definition                   *
//*************************************************

/**
 * @brief Create 'get_key_in' helper function that maps or merge target field value with the content of the some key in
 * the definition object, where the key is specified with a reference to another field.
 *
 * @param targetField target field of the helper
 * @param opArgs Vector of operation arguments containing numeric values to be converted.
 * @param buildCtx Shared pointer to the build context used for the conversion operation.
 * @param isMerge true if the helper is used in a merge operation (merge_key_in), false if only get the value
 * @return base::Expression
 */
TransformOp opBuilderHelperGetValueGeneric(const Reference& targetField,
                                           const std::vector<OpArg>& opArgs,
                                           const std::shared_ptr<const IBuildCtx>& buildCtx,
                                           bool isMerge = false,
                                           bool isRecurive = false);

/**
 * @brief Get the 'get_key_in' function helper builder
 *
 * @param targetField target field of the helper
 * @param opArgs Vector of operation arguments containing numeric values to be converted.
 * @param buildCtx Shared pointer to the build context used for the conversion operation.
 * @return builder
 */
TransformOp opBuilderHelperGetValue(const Reference& targetField,
                                    const std::vector<OpArg>& opArgs,
                                    const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Get the 'merge_key_in' function helper builder
 *
 * <field>: +merge_key_in/$<definition_object>|$<object_reference>/$<key>
 * @param targetField target field of the helper
 * @param opArgs Vector of operation arguments containing numeric values to be converted.
 * @param buildCtx Shared pointer to the build context used for the conversion operation.
 * @return builder
 */
TransformOp opBuilderHelperMergeValue(const Reference& targetField,
                                      const std::vector<OpArg>& opArgs,
                                      const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Get the 'merge_recursive_key_in' function helper builder
 *
 * <field>: +merge_key_in/$<definition_object>|$<object_reference>/$<key>
 * @param targetField target field of the helper
 * @param opArgs Vector of operation arguments containing numeric values to be converted.
 * @param buildCtx Shared pointer to the build context used for the conversion operation.
 * @return builder
 */
TransformOp opBuilderHelperMergeRecursiveValue(const Reference& targetField,
                                               const std::vector<OpArg>& opArgs,
                                               const std::shared_ptr<const IBuildCtx>& buildCtx);
} // namespace builder::builders

#endif // _OP_BUILDER_HELPER_MAP_H
