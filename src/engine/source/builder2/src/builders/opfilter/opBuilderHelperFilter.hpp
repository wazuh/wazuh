#ifndef _OP_BUILDER_HELPER_FILTER_H
#define _OP_BUILDER_HELPER_FILTER_H

#include "builders/types.hpp"

/*
 * The helper filter, builds a lifter that will chain rxcpp filter operation
 * Rxcpp filter expects a function that returns bool.
 *
 * Warning: this function never should throw an exception.
 */

namespace builder::builders::opfilter
{

//*************************************************
//*           String filters                      *
//*************************************************

/**
 * @brief Create `string_equal` helper function that filters events with a string
 * field equals to a value.
 *
 * The filter checks if a field in the JSON event is equal to a value.
 * Only pass events if the fields are equal (case sensitive) and the values are a string.
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * @param definitions handler with definitions
 * @return Expression The lifter with the `string_equal` filter.
 * @throw std::runtime_error if the parameter is not a string.
 */
FilterOp opBuilderHelperStringEqual(const Reference& targetField,
                                    const std::vector<OpArg>& opArgs,
                                    const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Create `string_not_equal` helper function that filters events with a string
 * field not equals to a value.
 *
 * The filter checks if a field in the JSON event is not  equal to a value.
 * Only do not pass events if the fields are equal (case sensitive) and the values are a
 * string.
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * @param definitions handler with definitions
 * @return Expression The lifter with the `string_not_equal` filter.
 * @throw std::runtime_error if the parameter is not a string.
 */
FilterOp opBuilderHelperStringNotEqual(const Reference& targetField,
                                       const std::vector<OpArg>& opArgs,
                                       const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Create `string_greater` helper function that filters events with a string
 * field greater than a value.
 *
 * The filter checks if the JSON event field <field> is greater than a <value>
 * or another field <$ref>. Only pass the filter if the event has both fields
 * of type string and passes the condition.
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * @param definitions handler with definitions
 * @return Expression The lifter with the `string_greater` filter.
 * @throw std::runtime_error if the parameter is not a string.
 */
FilterOp opBuilderHelperStringGreaterThan(const Reference& targetField,
                                          const std::vector<OpArg>& opArgs,
                                          const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Create `string_greater_or_equal` helper function that filters events with a string
 * field less or equals than a value.
 *
 * The filter checks if the JSON event field <field> is greater or equals than a <value>
 * or another field <$ref>. Only pass the filter if the event has both fields
 * of type string and passes the condition.
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * @param definitions handler with definitions
 * @return Expression The lifter with the `string_greater_or_equal` filter.
 * @throw std::runtime_error if the parameter is not a string.
 */
FilterOp opBuilderHelperStringGreaterThanEqual(const Reference& targetField,
                                               const std::vector<OpArg>& opArgs,
                                               const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Create `string_less` helper function that filters events with a string
 * field less than a value.
 *
 * The filter checks if the JSON event field <field> is less than a <value>
 * or another field <$ref>. Only pass the filter if the event has both fields
 * of type string and passes the condition.
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * @param definitions handler with definitions
 * @return Expression The lifter with the `string_less` filter.
 * @throw std::runtime_error if the parameter is not a string.
 */
FilterOp opBuilderHelperStringLessThan(const Reference& targetField,
                                       const std::vector<OpArg>& opArgs,
                                       const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Create `string_less_or_equal` helper function that filters events with a string
 * field less or equals than a value.
 *
 * The filter checks if the JSON event field <field> is less or equals than a <value>
 * or another field <$ref>. Only pass the filter if the event has both fields
 * of type string and passes the condition.
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * @param definitions handler with definitions
 * @return Expression The lifter with the `string_less_or_equal` filter.
 * @throw std::runtime_error if the parameter is not a string.
 */
FilterOp opBuilderHelperStringLessThanEqual(const Reference& targetField,
                                            const std::vector<OpArg>& opArgs,
                                            const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Create the `starts_with` helper function that allows to check if a field string
 * starts as a given one.
 *
 * The filter passes if both strings are equal (case sensitive) on the first N characters.
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * @param definitions handler with definitions
 * @return xpression The lifter with the `starts_with` filter.
 * @throw std::runtime_error if the parameter is not a string.
 */
FilterOp opBuilderHelperStringStarts(const Reference& targetField,
                                     const std::vector<OpArg>& opArgs,
                                     const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Create the `contains` helper function that allows to check if a field string
 * contains another one.
 *
 * The filter passes if the first one contains all of the seccond one.
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * @param definitions handler with definitions
 * @return xpression The lifter with the `contains` filter.
 * @throw std::runtime_error if the parameter is not a string.
 */
FilterOp opBuilderHelperStringContains(const Reference& targetField,
                                       const std::vector<OpArg>& opArgs,
                                       const std::shared_ptr<const IBuildCtx>& buildCtx);

//*************************************************
//*              Int filters                      *
//*************************************************

/**
 * @brief Builds helper integer equal operation.
 * Checks that the field is equal to an integer or another numeric field
 *
 * The filter checks if a field in the JSON event is equal to a value.
 * Only pass events if the fields are equal and the values are a integer.
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * @param definitions handler with definitions
 * @return Expression The lifter with the `int_equal` filter.
 * @throw std::runtime_error if the parameter is not a integer.
 */
FilterOp opBuilderHelperIntEqual(const Reference& targetField,
                                 const std::vector<OpArg>& opArgs,
                                 const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Builds helper integer not equal operation.
 * Checks that the field is not equal to an integer or another numeric field
 *
 * The filter checks if a field in the JSON event is not equal to a value.
 * Only pass events if the fields are not equal and the values are a integer.
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * @param definitions handler with definitions
 * @return Expression The lifter with the `int_not_equal` filter.
 * @throw std::runtime_error if the parameter is not a integer.
 */
FilterOp opBuilderHelperIntNotEqual(const Reference& targetField,
                                    const std::vector<OpArg>& opArgs,
                                    const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Builds helper integer less than operation.
 * Checks that the field is less than to an integer or another numeric field
 *
 * The filter checks if a field in the JSON event is less than a value.
 * Only pass events if the fields are less than and the values are a integer.
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * @param definitions handler with definitions
 * @return Expression The lifter with the `int_less` filter.
 * @throw std::runtime_error if the parameter is not a integer.
 */
FilterOp opBuilderHelperIntLessThan(const Reference& targetField,
                                    const std::vector<OpArg>& opArgs,
                                    const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Builds helper integer less than equal operation.
 * Checks that the field is less than equal to an integer or another numeric field
 *
 * The filter checks if a field in the JSON event is less than equal a value.
 * Only pass events if the fields are less than equal and the values are a integer.
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * @param definitions handler with definitions
 * @return Expression The lifter with the `int_less_or_equal` filter.
 * @throw std::runtime_error if the parameter is not a integer.
 */
FilterOp opBuilderHelperIntLessThanEqual(const Reference& targetField,
                                         const std::vector<OpArg>& opArgs,
                                         const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Builds helper integer greater than operation.
 * Checks that the field is greater than to an integer or another numeric field
 *
 * The filter checks if a field in the JSON event is greater than a value.
 * Only pass events if the fields are greater than and the values are a integer.
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * @param definitions handler with definitions
 * @return Expression The lifter with the `int_greater` filter.
 * @throw std::runtime_error if the parameter is not a integer.
 */

FilterOp opBuilderHelperIntGreaterThan(const Reference& targetField,
                                       const std::vector<OpArg>& opArgs,
                                       const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Builds helper integer greater than equal operation.
 * Checks that the field is greater than equal to an integer or another numeric field
 *
 * The filter checks if a field in the JSON event is greater than equal a value.
 * Only pass events if the fields are greater than equal and the values are a integer.
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * @param definitions handler with definitions
 * @return Expression The lifter with the `int_greater_or_equal` filter.
 * @throw std::runtime_error if the parameter is not a integer.
 */
FilterOp opBuilderHelperIntGreaterThanEqual(const Reference& targetField,
                                            const std::vector<OpArg>& opArgs,
                                            const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Builds helper regex match operation.
 * Checks that the field value matches a regular expression
 *
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * @param definitions handler with definitions
 * @return Expression The lifter with the `regex` filter.
 */
FilterOp opBuilderHelperRegexMatch(const Reference& targetField,
                                   const std::vector<OpArg>& opArgs,
                                   const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Builds helper regex not match operation.
 * Checks that the field value doesn't match a regular expression
 *
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * @param definitions handler with definitions
 * @return Expression The lifter with the `regex_not` filter.
 */
FilterOp opBuilderHelperRegexNotMatch(const Reference& targetField,
                                      const std::vector<OpArg>& opArgs,
                                      const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Create `ip_cidr_match` helper function that filters events if the field
 * is in the specified CIDR range.
 *
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * @param definitions handler with definitions
 * @return Expression The lifter with the `ip_cidr_match` filter.
 * @throw  std::runtime_error if the parameter is not a cidr.
 */
FilterOp opBuilderHelperIPCIDR(const Reference& targetField,
                               const std::vector<OpArg>& opArgs,
                               const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Create `array_contains` helper function that filters events if the field
 * is an array and contains one of the specified values.
 *
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * @param definitions handler with definitions
 * @return FilterOp
 *
 * @throws std::runtime_error if cannot create the filter.
 */
FilterOp opBuilderHelperContainsString(const Reference& targetField,
                                       const std::vector<OpArg>& opArgs,
                                       const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Create `array_not_contains` helper function that filters events if the field
 * is an array and does not contains any of the specified values.
 *
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * @param definitions handler with definitions
 * @return FilterOp
 *
 * @throws std::runtime_error if cannot create the filter.
 */
FilterOp opBuilderHelperNotContainsString(const Reference& targetField,
                                          const std::vector<OpArg>& opArgs,
                                          const std::shared_ptr<const IBuildCtx>& buildCtx);

//*************************************************
//*                Type filters                   *
//*************************************************

/**
 * @brief Create `is_number` helper function that filters events which field is not of the
 * expected type.
 *
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * @param definitions handler with definitions
 * @return FilterOp
 */
FilterOp opBuilderHelperIsNumber(const Reference& targetField,
                                 const std::vector<OpArg>& opArgs,
                                 const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Create `is_not_number` helper function that filters events which field is not of
 * the expected type.
 *
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * @param definitions handler with definitions
 * @return FilterOp
 */
FilterOp opBuilderHelperIsNotNumber(const Reference& targetField,
                                    const std::vector<OpArg>& opArgs,
                                    const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Create `is_string` helper function that filters events which field is not of
 * the expected type.
 *
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * @param definitions handler with definitions
 * @return FilterOp
 */
FilterOp opBuilderHelperIsString(const Reference& targetField,
                                 const std::vector<OpArg>& opArgs,
                                 const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Create `is_not_string` helper function that filters events which field is not
 * of the expected type.
 *
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * @param definitions handler with definitions
 * @return FilterOp
 */
FilterOp opBuilderHelperIsNotString(const Reference& targetField,
                                    const std::vector<OpArg>& opArgs,
                                    const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Create `is_boolean` helper function that filters events which field is not of the
 * expected type.
 *
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * @param definitions handler with definitions
 * @return FilterOp
 */
FilterOp opBuilderHelperIsBool(const Reference& targetField,
                               const std::vector<OpArg>& opArgs,
                               const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Create `is_not_boolean` helper function that filters events which field is not of
 * the expected type.
 *
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * @param definitions handler with definitions
 * @return FilterOp
 */
FilterOp opBuilderHelperIsNotBool(const Reference& targetField,
                                  const std::vector<OpArg>& opArgs,
                                  const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Create `is_array` helper function that filters events which field is not of
 * the expected type.
 *
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * @param definitions handler with definitions
 * @return FilterOp
 */
FilterOp opBuilderHelperIsArray(const Reference& targetField,
                                const std::vector<OpArg>& opArgs,
                                const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Create `is_not_array` helper function that filters events which field is not
 * of the expected type.
 *
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * @param definitions handler with definitions
 * @return FilterOp
 */
FilterOp opBuilderHelperIsNotArray(const Reference& targetField,
                                   const std::vector<OpArg>& opArgs,
                                   const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Create `is_object` helper function that filters events which field is not of
 * the expected type.
 *
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * @param definitions handler with definitions
 * @return FilterOp
 */
FilterOp opBuilderHelperIsObject(const Reference& targetField,
                                 const std::vector<OpArg>& opArgs,
                                 const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Create `is_not_object` helper function that filters events which field is not
 * of the expected type.
 *
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * @param definitions handler with definitions
 * @return FilterOp
 */
FilterOp opBuilderHelperIsNotObject(const Reference& targetField,
                                    const std::vector<OpArg>& opArgs,
                                    const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Create `is_null` helper function that filters events which field is not of the
 * expected type.
 *
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * @param definitions handler with definitions
 * @return FilterOp
 */
FilterOp opBuilderHelperIsNull(const Reference& targetField,
                               const std::vector<OpArg>& opArgs,
                               const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Create `is_not_null` helper function that filters events which field is not of
 * the expected type.
 *
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * @param definitions handler with definitions
 * @return FilterOp
 */
FilterOp opBuilderHelperIsNotNull(const Reference& targetField,
                                  const std::vector<OpArg>& opArgs,
                                  const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Create `is_true` helper function that filters events which field is not of the
 * expected type.
 *
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * @param definitions handler with definitions
 * @return FilterOp
 */
FilterOp opBuilderHelperIsTrue(const Reference& targetField,
                               const std::vector<OpArg>& opArgs,
                               const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Create `is_false` helper function that filters events which field is not of
 * the expected type.
 *
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * @param definitions handler with definitions
 * @return FilterOp
 */
FilterOp opBuilderHelperIsFalse(const Reference& targetField,
                                const std::vector<OpArg>& opArgs,
                                const std::shared_ptr<const IBuildCtx>& buildCtx);

//*************************************************
//*              Definition filters               *
//*************************************************

/**
 * @brief Create `match_value` helper function that filters events which field
 * value is present in the specified definition array.
 * <field>: +match_value/$<definition_array>|$<array_reference>
 *
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * @param definitions handler with definitions
 * @return FilterOp
 */
FilterOp opBuilderHelperMatchValue(const Reference& targetField,
                                   const std::vector<OpArg>& opArgs,
                                   const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Create `match_key` helper function that filters events which field
 * value is present as a key in the specified definition object.
 * <field>: +match_key/$<definition_object>|$<object_reference>
 *
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * @param definitions handler with definitions
 * @param schema schema to validate fields
 * @return FilterOp
 */
FilterOp opBuilderHelperMatchKey(const Reference& targetField,
                                 const std::vector<OpArg>& opArgs,
                                 const std::shared_ptr<const IBuildCtx>& buildCtx);

} // namespace builder::builders::opfilter

#endif // _OP_BUILDER_HELPER_FILTER_H
