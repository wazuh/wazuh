#ifndef _OP_BUILDER_HELPER_FILTER_H
#define _OP_BUILDER_HELPER_FILTER_H

#include <any>

#include "expression.hpp"

/*
 * The helper filter, builds a lifter that will chain rxcpp filter operation
 * Rxcpp filter expects a function that returns bool.
 *
 * Warning: this function never should throw an exception.
 */

namespace builder::internals::builders
{

/**
 * @brief Create `ef_exists` helper function that filters events that contains specified
 * field.
 *
 * The filter checks if a field exists in the JSON event `e`.
 * @param definition The filter definition.
 * @return Expression The lifter with the `ef_exists` filter.
 */
base::Expression opBuilderHelperExists(const std::any& definition);

/**
 * @brief Create `ef_not_exists` helper function that filters events that not contains
 * specified field.
 *
 * The filter checks if a field not exists in the JSON event `e`.
 * @param definition The filter definition.
 * @return Expression The lifter with the `ef_not_exists` filter.
 */
base::Expression opBuilderHelperNotExists(const std::any& definition);

//*************************************************
//*           String filters                      *
//*************************************************

/**
 * @brief Create `s_eq` helper function that filters events with a string
 * field equals to a value.
 *
 * The filter checks if a field in the JSON event is equal to a value.
 * Only pass events if the fields are equal (case sensitive) and the values are a string.
 * @param definition The filter definition.
 * @return Expression The lifter with the `s_eq` filter.
 * @throw std::runtime_error if the parameter is not a string.
 */
base::Expression opBuilderHelperStringEqual(const std::any& definition);

/**
 * @brief Create `s_ne` helper function that filters events with a string
 * field not equals to a value.
 *
 * The filter checks if a field in the JSON event is not  equal to a value.
 * Only do not pass events if the fields are equal (case sensitive) and the values are a
 * string.
 * @param definition The filter definition.
 * @return Expression The lifter with the `s_ne` filter.
 * @throw std::runtime_error if the parameter is not a string.
 */
base::Expression opBuilderHelperStringNotEqual(const std::any& definition);

/**
 * @brief Create `s_gt` helper function that filters events with a string
 * field greater than a value.
 *
 * The filter checks if the JSON event field <field> is greater than a <value>
 * or another field <$ref>. Only pass the filter if the event has both fields
 * of type string and passes the condition.
 * @param definition The filter definition.
 * @return Expression The lifter with the `s_gt` filter.
 * @throw std::runtime_error if the parameter is not a string.
 */
base::Expression opBuilderHelperStringGreaterThan(const std::any& definition);

/**
 * @brief Create `s_ge` helper function that filters events with a string
 * field less or equals than a value.
 *
 * The filter checks if the JSON event field <field> is greater or equals than a <value>
 * or another field <$ref>. Only pass the filter if the event has both fields
 * of type string and passes the condition.
 * @param definition The filter definition.
 * @return Expression The lifter with the `s_ge` filter.
 * @throw std::runtime_error if the parameter is not a string.
 */
base::Expression opBuilderHelperStringGreaterThanEqual(const std::any& definition);

/**
 * @brief Create `s_lt` helper function that filters events with a string
 * field less than a value.
 *
 * The filter checks if the JSON event field <field> is less than a <value>
 * or another field <$ref>. Only pass the filter if the event has both fields
 * of type string and passes the condition.
 * @param definition The filter definition.
 * @return Expression The lifter with the `s_lt` filter.
 * @throw std::runtime_error if the parameter is not a string.
 */
base::Expression opBuilderHelperStringLessThan(const std::any& definition);

/**
 * @brief Create `s_le` helper function that filters events with a string
 * field less or equals than a value.
 *
 * The filter checks if the JSON event field <field> is less or equals than a <value>
 * or another field <$ref>. Only pass the filter if the event has both fields
 * of type string and passes the condition.
 * @param definition The filter definition.
 * @return Expression The lifter with the `s_le` filter.
 * @throw std::runtime_error if the parameter is not a string.
 */
base::Expression opBuilderHelperStringLessThanEqual(const std::any& definition);

/**
 * @brief Create the `s_starts` helper function that allows to check if a field string
 * starts as a given one.
 *
 * The filter passes if both strings are equal (case sensitive) on the first N characters.
 * @param definition The filter definition.
 * @return xpression The lifter with the `s_starts` filter.
 * @throw std::runtime_error if the parameter is not a string.
 */
base::Expression opBuilderHelperStringStarts(const std::any& definition);

//*************************************************
//*              Int filters                      *
//*************************************************

/**
 * @brief Builds helper integer equal operation.
 * Checks that the field is equal to an integer or another numeric field
 *
 * The filter checks if a field in the JSON event is equal to a value.
 * Only pass events if the fields are equal and the values are a integer.
 * @param definition Definition of the operation to be built
 * @return Expression The lifter with the `i_eq` filter.
 * @throw std::runtime_error if the parameter is not a integer.
 */
base::Expression opBuilderHelperIntEqual(const std::any& definition);

/**
 * @brief Builds helper integer not equal operation.
 * Checks that the field is not equal to an integer or another numeric field
 *
 * The filter checks if a field in the JSON event is not equal to a value.
 * Only pass events if the fields are not equal and the values are a integer.
 * @param definition Definition of the operation to be built
 * @return Expression The lifter with the `i_ne` filter.
 * @throw std::runtime_error if the parameter is not a integer.
 */
base::Expression opBuilderHelperIntNotEqual(const std::any& definition);

/**
 * @brief Builds helper integer less than operation.
 * Checks that the field is less than to an integer or another numeric field
 *
 * The filter checks if a field in the JSON event is less than a value.
 * Only pass events if the fields are less than and the values are a integer.
 * @param definition Definition of the operation to be built
 * @return Expression The lifter with the `i_lt` filter.
 * @throw std::runtime_error if the parameter is not a integer.
 */
base::Expression opBuilderHelperIntLessThan(const std::any& definition);

/**
 * @brief Builds helper integer less than equal operation.
 * Checks that the field is less than equal to an integer or another numeric field
 *
 * The filter checks if a field in the JSON event is less than equal a value.
 * Only pass events if the fields are less than equal and the values are a integer.
 * @param definition Definition of the operation to be built
 * @return Expression The lifter with the `i_le` filter.
 * @throw std::runtime_error if the parameter is not a integer.
 */
base::Expression opBuilderHelperIntLessThanEqual(const std::any& definition);

/**
 * @brief Builds helper integer greater than operation.
 * Checks that the field is greater than to an integer or another numeric field
 *
 * The filter checks if a field in the JSON event is greater than a value.
 * Only pass events if the fields are greater than and the values are a integer.
 * @param definition Definition of the operation to be built
 * @return Expression The lifter with the `i_gt` filter.
 * @throw std::runtime_error if the parameter is not a integer.
 */

base::Expression opBuilderHelperIntGreaterThan(const std::any& definition);

/**
 * @brief Builds helper integer greater than equal operation.
 * Checks that the field is greater than equal to an integer or another numeric field
 *
 * The filter checks if a field in the JSON event is greater than equal a value.
 * Only pass events if the fields are greater than equal and the values are a integer.
 * @param definition Definition of the operation to be built
 * @return Expression The lifter with the `i_ge` filter.
 * @throw std::runtime_error if the parameter is not a integer.
 */
base::Expression opBuilderHelperIntGreaterThanEqual(const std::any& definition);

/**
 * @brief Builds helper regex match operation.
 * Checks that the field value matches a regular expression
 *
 * @param definition Definition of the operation to be built
 * @return Expression The lifter with the `regex` filter.
 */
base::Expression opBuilderHelperRegexMatch(const std::any& definition);

/**
 * @brief Builds helper regex not match operation.
 * Checks that the field value doesn't match a regular expression
 *
 * @param definition Definition of the operation to be built
 * @return Expression The lifter with the `regex_not` filter.
 */
base::Expression opBuilderHelperRegexNotMatch(const std::any& definition);

/**
 * @brief Create `ip_cidr` helper function that filters events if the field
 * is in the specified CIDR range.
 *
 * @param definition The filter definition.
 * @return Expression The lifter with the `ip_cidr` filter.
 * @throw  std::runtime_error if the parameter is not a cidr.
 */
base::Expression opBuilderHelperIPCIDR(const std::any& definition);

/**
 * @brief Create `a_contains` helper function that filters events if the field
 * is an array and contains one of the specified values.
 *
 * @param definition The filter definition.
 * @return base::Expression
 *
 * @throws std::runtime_error if cannot create the filter.
 */
base::Expression opBuilderHelperContainsString(const std::any& definition);

//*************************************************
//*                Type filters                   *
//*************************************************

/**
 * @brief Create `t_is_num` helper function that filters events which field is not of the
 * expected type.
 *
 * @param definition The filter definition.
 * @return base::Expression
 */
base::Expression opBuilderHelperIsNumber(const std::any& definition);

/**
 * @brief Create `t_is_not_num` helper function that filters events which field is not of
 * the expected type.
 *
 * @param definition The filter definition.
 * @return base::Expression
 */
base::Expression opBuilderHelperIsNotNumber(const std::any& definition);

/**
 * @brief Create `t_is_string` helper function that filters events which field is not of
 * the expected type.
 *
 * @param definition The filter definition.
 * @return base::Expression
 */
base::Expression opBuilderHelperIsString(const std::any& definition);

/**
 * @brief Create `t_is_not_string` helper function that filters events which field is not
 * of the expected type.
 *
 * @param definition The filter definition.
 * @return base::Expression
 */
base::Expression opBuilderHelperIsNotString(const std::any& definition);

/**
 * @brief Create `t_is_bool` helper function that filters events which field is not of the
 * expected type.
 *
 * @param definition The filter definition.
 * @return base::Expression
 */
base::Expression opBuilderHelperIsBool(const std::any& definition);

/**
 * @brief Create `t_is_not_bool` helper function that filters events which field is not of
 * the expected type.
 *
 * @param definition The filter definition.
 * @return base::Expression
 */
base::Expression opBuilderHelperIsNotBool(const std::any& definition);

/**
 * @brief Create `t_is_array` helper function that filters events which field is not of
 * the expected type.
 *
 * @param definition The filter definition.
 * @return base::Expression
 */
base::Expression opBuilderHelperIsArray(const std::any& definition);

/**
 * @brief Create `t_is_not_array` helper function that filters events which field is not
 * of the expected type.
 *
 * @param definition The filter definition.
 * @return base::Expression
 */
base::Expression opBuilderHelperIsNotArray(const std::any& definition);

/**
 * @brief Create `t_is_object` helper function that filters events which field is not of
 * the expected type.
 *
 * @param definition The filter definition.
 * @return base::Expression
 */
base::Expression opBuilderHelperIsObject(const std::any& definition);

/**
 * @brief Create `t_is_not_object` helper function that filters events which field is not
 * of the expected type.
 *
 * @param definition The filter definition.
 * @return base::Expression
 */
base::Expression opBuilderHelperIsNotObject(const std::any& definition);

/**
 * @brief Create `t_is_null` helper function that filters events which field is not of the
 * expected type.
 *
 * @param definition The filter definition.
 * @return base::Expression
 */
base::Expression opBuilderHelperIsNull(const std::any& definition);

/**
 * @brief Create `t_is_not_null` helper function that filters events which field is not of
 * the expected type.
 *
 * @param definition The filter definition.
 * @return base::Expression
 */
base::Expression opBuilderHelperIsNotNull(const std::any& definition);

/**
 * @brief Create `t_is_true` helper function that filters events which field is not of the
 * expected type.
 *
 * @param definition The filter definition.
 * @return base::Expression
 */
base::Expression opBuilderHelperIsTrue(const std::any& definition);

/**
 * @brief Create `t_is_false` helper function that filters events which field is not of
 * the expected type.
 *
 * @param definition The filter definition.
 * @return base::Expression
 */
base::Expression opBuilderHelperIsFalse(const std::any& definition);

} // namespace builder::internals::builders

#endif // _OP_BUILDER_HELPER_FILTER_H
