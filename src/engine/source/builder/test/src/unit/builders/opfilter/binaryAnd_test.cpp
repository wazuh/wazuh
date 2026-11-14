// SPDX-License-Identifier: AGPL-3.0-or-later
#include "builders/baseBuilders_test.hpp"
#include "builders/opfilter/opBuilderHelperFilter.hpp"

// has_any_bit(mask): true when (target & mask) != 0. The mask and the target are a hexadecimal string, with or
// without the 0x/0X prefix and in any case, of at most 16 digits (64 bits), or a non-negative JSON integer.

namespace filterbuildtest
{

INSTANTIATE_TEST_SUITE_P(
    Builders,
    FilterBuilderTest,
    testing::Values(
        // Wrong number of arguments
        FilterT({}, opfilter::opBuilderHelperBinaryAnd, FAILURE()),
        FilterT({makeValue(R"("0x1")"), makeValue(R"("0x2")")}, opfilter::opBuilderHelperBinaryAnd, FAILURE()),
        // The mask must be a value
        FilterT({makeRef("ref")}, opfilter::opBuilderHelperBinaryAnd, FAILURE()),
        // Hexadecimal string masks: with or without the 0x/0X prefix, any case
        FilterT({makeValue(R"("0x1")")}, opfilter::opBuilderHelperBinaryAnd, SUCCESS()),
        FilterT({makeValue(R"("0X1F")")}, opfilter::opBuilderHelperBinaryAnd, SUCCESS()),
        FilterT({makeValue(R"("0x1f")")}, opfilter::opBuilderHelperBinaryAnd, SUCCESS()),
        FilterT({makeValue(R"("1f")")}, opfilter::opBuilderHelperBinaryAnd, SUCCESS()),
        FilterT({makeValue(R"("1F")")}, opfilter::opBuilderHelperBinaryAnd, SUCCESS()),
        FilterT({makeValue(R"("0xAb")")}, opfilter::opBuilderHelperBinaryAnd, SUCCESS()),
        FilterT({makeValue(R"("F0")")}, opfilter::opBuilderHelperBinaryAnd, SUCCESS()),
        // Up to 16 hexadecimal digits (64 bits)
        FilterT({makeValue(R"("0xFFFFFFFFFFFFFFFF")")}, opfilter::opBuilderHelperBinaryAnd, SUCCESS()),
        FilterT({makeValue(R"("FFFFFFFFFFFFFFFF")")}, opfilter::opBuilderHelperBinaryAnd, SUCCESS()),
        FilterT({makeValue(R"("0x8000000000000000")")}, opfilter::opBuilderHelperBinaryAnd, SUCCESS()),
        FilterT({makeValue(R"("0x0000000000000001")")}, opfilter::opBuilderHelperBinaryAnd, SUCCESS()),
        FilterT({makeValue(R"("0x10000000000000000")")}, opfilter::opBuilderHelperBinaryAnd, FAILURE()),
        FilterT({makeValue(R"("10000000000000000")")}, opfilter::opBuilderHelperBinaryAnd, FAILURE()),
        // 17 digits are rejected even when the value fits
        FilterT({makeValue(R"("0x00000000000000001")")}, opfilter::opBuilderHelperBinaryAnd, FAILURE()),
        // Invalid hexadecimal strings
        FilterT({makeValue(R"("nothex")")}, opfilter::opBuilderHelperBinaryAnd, FAILURE()),
        FilterT({makeValue(R"("0xG1")")}, opfilter::opBuilderHelperBinaryAnd, FAILURE()),
        FilterT({makeValue(R"("1F ")")}, opfilter::opBuilderHelperBinaryAnd, FAILURE()),
        FilterT({makeValue(R"(" 1F")")}, opfilter::opBuilderHelperBinaryAnd, FAILURE()),
        FilterT({makeValue(R"("-1")")}, opfilter::opBuilderHelperBinaryAnd, FAILURE()),
        FilterT({makeValue(R"("0x")")}, opfilter::opBuilderHelperBinaryAnd, FAILURE()),
        FilterT({makeValue(R"("0X")")}, opfilter::opBuilderHelperBinaryAnd, FAILURE()),
        FilterT({makeValue(R"("")")}, opfilter::opBuilderHelperBinaryAnd, FAILURE()),
        FilterT({makeValue(R"("0x0x1")")}, opfilter::opBuilderHelperBinaryAnd, FAILURE()),
        // Mask 0 is rejected in every spelling
        FilterT({makeValue(R"("0x0")")}, opfilter::opBuilderHelperBinaryAnd, FAILURE()),
        FilterT({makeValue(R"("0X00")")}, opfilter::opBuilderHelperBinaryAnd, FAILURE()),
        FilterT({makeValue(R"("0")")}, opfilter::opBuilderHelperBinaryAnd, FAILURE()),
        FilterT({makeValue(R"("0000000000000000")")}, opfilter::opBuilderHelperBinaryAnd, FAILURE()),
        FilterT({makeValue(R"(0)")}, opfilter::opBuilderHelperBinaryAnd, FAILURE()),
        // Non-negative integer masks
        FilterT({makeValue(R"(1)")}, opfilter::opBuilderHelperBinaryAnd, SUCCESS()),
        FilterT({makeValue(R"(255)")}, opfilter::opBuilderHelperBinaryAnd, SUCCESS()),
        FilterT({makeValue(R"(9223372036854775807)")}, opfilter::opBuilderHelperBinaryAnd, SUCCESS()),
        FilterT({makeValue(R"(-1)")}, opfilter::opBuilderHelperBinaryAnd, FAILURE()),
        FilterT({makeValue(R"(-255)")}, opfilter::opBuilderHelperBinaryAnd, FAILURE()),
        // Other JSON types
        FilterT({makeValue(R"(1.1)")}, opfilter::opBuilderHelperBinaryAnd, FAILURE()),
        FilterT({makeValue(R"(1.0)")}, opfilter::opBuilderHelperBinaryAnd, FAILURE()),
        FilterT({makeValue(R"(true)")}, opfilter::opBuilderHelperBinaryAnd, FAILURE()),
        FilterT({makeValue(R"(false)")}, opfilter::opBuilderHelperBinaryAnd, FAILURE()),
        FilterT({makeValue(R"([])")}, opfilter::opBuilderHelperBinaryAnd, FAILURE()),
        FilterT({makeValue(R"([1])")}, opfilter::opBuilderHelperBinaryAnd, FAILURE()),
        FilterT({makeValue(R"({})")}, opfilter::opBuilderHelperBinaryAnd, FAILURE()),
        FilterT({makeValue(R"(null)")}, opfilter::opBuilderHelperBinaryAnd, FAILURE())),
    testNameFormatter<FilterBuilderTest>("HasAnyBit"));
} // namespace filterbuildtest

namespace filteroperatestest
{
INSTANTIATE_TEST_SUITE_P(
    Builders,
    FilterOperationTest,
    testing::Values(
        // Hexadecimal string target, hexadecimal string mask
        FilterT(
            R"({"target": "0xF0"})", opfilter::opBuilderHelperBinaryAnd, "target", {makeValue(R"("0xF0")")}, SUCCESS()),
        FilterT(
            R"({"target": "0x0F"})", opfilter::opBuilderHelperBinaryAnd, "target", {makeValue(R"("0xF0")")}, FAILURE()),
        FilterT(
            R"({"target": "0xFF"})", opfilter::opBuilderHelperBinaryAnd, "target", {makeValue(R"("0xF0")")}, SUCCESS()),
        FilterT(
            R"({"target": "0x00"})", opfilter::opBuilderHelperBinaryAnd, "target", {makeValue(R"("0xF0")")}, FAILURE()),
        FilterT(
            R"({"target": "0x10"})", opfilter::opBuilderHelperBinaryAnd, "target", {makeValue(R"("0x10")")}, SUCCESS()),
        FilterT(
            R"({"target": "0x20"})", opfilter::opBuilderHelperBinaryAnd, "target", {makeValue(R"("0x10")")}, FAILURE()),
        // Any bit in common is enough
        FilterT(
            R"({"target": "0x01"})", opfilter::opBuilderHelperBinaryAnd, "target", {makeValue(R"("0xFF")")}, SUCCESS()),
        FilterT(
            R"({"target": "0x80"})", opfilter::opBuilderHelperBinaryAnd, "target", {makeValue(R"("0x81")")}, SUCCESS()),
        // Prefix and case of the target do not matter
        FilterT(
            R"({"target": "0X1F"})", opfilter::opBuilderHelperBinaryAnd, "target", {makeValue(R"("0x10")")}, SUCCESS()),
        FilterT(
            R"({"target": "1f"})", opfilter::opBuilderHelperBinaryAnd, "target", {makeValue(R"("0x10")")}, SUCCESS()),
        FilterT(R"({"target": "1F"})", opfilter::opBuilderHelperBinaryAnd, "target", {makeValue(R"("1")")}, SUCCESS()),
        FilterT(
            R"({"target": "0xaB"})", opfilter::opBuilderHelperBinaryAnd, "target", {makeValue(R"("0xAb")")}, SUCCESS()),
        FilterT(
            R"({"target": "0x20"})", opfilter::opBuilderHelperBinaryAnd, "target", {makeValue(R"("1f")")}, FAILURE()),
        FilterT(
            R"({"target": "20"})", opfilter::opBuilderHelperBinaryAnd, "target", {makeValue(R"("0X1F")")}, FAILURE()),
        // 64-bit values
        FilterT(R"({"target": "0x8000000000000000"})",
                opfilter::opBuilderHelperBinaryAnd,
                "target",
                {makeValue(R"("0x8000000000000000")")},
                SUCCESS()),
        FilterT(R"({"target": "0xFFFFFFFFFFFFFFFF"})",
                opfilter::opBuilderHelperBinaryAnd,
                "target",
                {makeValue(R"("0x1")")},
                SUCCESS()),
        FilterT(R"({"target": "FFFFFFFFFFFFFFFF"})",
                opfilter::opBuilderHelperBinaryAnd,
                "target",
                {makeValue(R"("8000000000000000")")},
                SUCCESS()),
        FilterT(R"({"target": "0x7FFFFFFFFFFFFFFF"})",
                opfilter::opBuilderHelperBinaryAnd,
                "target",
                {makeValue(R"("0x8000000000000000")")},
                FAILURE()),
        // 17 digits in the target: not a valid hexadecimal string
        FilterT(R"({"target": "0x10000000000000000"})",
                opfilter::opBuilderHelperBinaryAnd,
                "target",
                {makeValue(R"("0x1")")},
                FAILURE()),
        // Non-negative integer target
        FilterT(R"({"target": 16})", opfilter::opBuilderHelperBinaryAnd, "target", {makeValue(R"("0x10")")}, SUCCESS()),
        FilterT(R"({"target": 15})", opfilter::opBuilderHelperBinaryAnd, "target", {makeValue(R"("0x10")")}, FAILURE()),
        FilterT(
            R"({"target": 255})", opfilter::opBuilderHelperBinaryAnd, "target", {makeValue(R"("0x80")")}, SUCCESS()),
        FilterT(R"({"target": 0})", opfilter::opBuilderHelperBinaryAnd, "target", {makeValue(R"("0x1")")}, FAILURE()),
        FilterT(R"({"target": -1})", opfilter::opBuilderHelperBinaryAnd, "target", {makeValue(R"("0x1")")}, FAILURE()),
        FilterT(R"({"target": 9223372036854775807})",
                opfilter::opBuilderHelperBinaryAnd,
                "target",
                {makeValue(R"("0x4000000000000000")")},
                SUCCESS()),
        // Integer mask
        FilterT(
            R"({"target": "0xF0"})", opfilter::opBuilderHelperBinaryAnd, "target", {makeValue(R"(240)")}, SUCCESS()),
        FilterT(
            R"({"target": "0x0F"})", opfilter::opBuilderHelperBinaryAnd, "target", {makeValue(R"(240)")}, FAILURE()),
        FilterT(R"({"target": 3})", opfilter::opBuilderHelperBinaryAnd, "target", {makeValue(R"(2)")}, SUCCESS()),
        FilterT(R"({"target": 4})", opfilter::opBuilderHelperBinaryAnd, "target", {makeValue(R"(3)")}, FAILURE()),
        FilterT(R"({"target": 255})", opfilter::opBuilderHelperBinaryAnd, "target", {makeValue(R"(1)")}, SUCCESS()),
        FilterT(R"({"target": "ff"})", opfilter::opBuilderHelperBinaryAnd, "target", {makeValue(R"(256)")}, FAILURE()),
        // Target is neither a hexadecimal string nor a non-negative integer
        FilterT(R"({"target": "nothex"})",
                opfilter::opBuilderHelperBinaryAnd,
                "target",
                {makeValue(R"("0x1")")},
                FAILURE()),
        FilterT(
            R"({"target": "0x"})", opfilter::opBuilderHelperBinaryAnd, "target", {makeValue(R"("0x1")")}, FAILURE()),
        FilterT(R"({"target": ""})", opfilter::opBuilderHelperBinaryAnd, "target", {makeValue(R"("0x1")")}, FAILURE()),
        FilterT(
            R"({"target": "0xG1"})", opfilter::opBuilderHelperBinaryAnd, "target", {makeValue(R"("0xFF")")}, FAILURE()),
        FilterT(
            R"({"target": "-1"})", opfilter::opBuilderHelperBinaryAnd, "target", {makeValue(R"("0xFF")")}, FAILURE()),
        FilterT(R"({"target": 1.5})", opfilter::opBuilderHelperBinaryAnd, "target", {makeValue(R"("0x1")")}, FAILURE()),
        FilterT(
            R"({"target": true})", opfilter::opBuilderHelperBinaryAnd, "target", {makeValue(R"("0x1")")}, FAILURE()),
        FilterT(
            R"({"target": null})", opfilter::opBuilderHelperBinaryAnd, "target", {makeValue(R"("0x1")")}, FAILURE()),
        FilterT(
            R"({"target": ["0x1"]})", opfilter::opBuilderHelperBinaryAnd, "target", {makeValue(R"("0x1")")}, FAILURE()),
        FilterT(R"({"target": {"a": "0x1"}})",
                opfilter::opBuilderHelperBinaryAnd,
                "target",
                {makeValue(R"("0x1")")},
                FAILURE()),
        // Missing target field
        FilterT(
            R"({"other": "0x10"})", opfilter::opBuilderHelperBinaryAnd, "target", {makeValue(R"("0x10")")}, FAILURE())),
    testNameFormatter<FilterOperationTest>("HasAnyBit"));
} // namespace filteroperatestest
