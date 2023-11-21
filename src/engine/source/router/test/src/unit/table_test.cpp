#include <gtest/gtest.h>

#include <tuple>
#include <utility>
#include <vector>

#include "table.hpp"

namespace ri = router::internal;

using ValueType = std::string;
struct EntryTest
{
    std::string name;
    std::size_t priority;
    ValueType value;
};

/**
 * @brief Check if the entry is in the table.
 *
 * @param table The table to check.
 * @param entry The entry to check.
 * @param inserted true if the entry should be in the table, false otherwise.
 */
void checkEntryTable(const ri::Table<ValueType>& table, const EntryTest& entry, bool inserted)
{
    if (inserted)
    {
        // Check if the name and priority exists
        EXPECT_TRUE(table.nameExists(entry.name));
        EXPECT_TRUE(table.priorityExists(entry.priority));

        // Check if the name and the priority is the same entry
        const auto& tEntry = table.get(entry.name);
        EXPECT_EQ(tEntry, entry.value);
    }
    else
    {
        // Insert only fails if the name or the priority is already used
        bool res = table.nameExists(entry.name) || table.priorityExists(entry.priority);
        EXPECT_TRUE(res);
    }
}

/************************************************
 *          Test the insert/get method.
 ************************************************/
using InsertT = std::vector<std::pair<EntryTest, bool>>;
using InsertTest = ::testing::TestWithParam<InsertT>;
static int g_insertCount = 0;
class EasyInsert
{
private:
    InsertT m_insert;

public:
    EasyInsert() = default;

    EasyInsert& add(const std::string& name, std::size_t priority, bool expected)
    {
        EntryTest entry {name, priority, std::to_string(g_insertCount++)};
        m_insert.emplace_back(std::move(entry), expected);
        return *this;
    }

    // Cast EasyInsert to InsertT
    operator InsertT() const { return m_insert; }
};

TEST_P(InsertTest, Insert)
{
    auto& arrayTest = GetParam();
    ri::Table<ValueType> table;
    for (auto& [entry, expected] : arrayTest)
    {
        EXPECT_EQ(table.insert(entry.name, entry.priority, ValueType(entry.value)), expected);
        checkEntryTable(table, entry, expected);
    }
}

INSTANTIATE_TEST_SUITE_P(Table,
                         InsertTest,
                         ::testing::Values(
                             // Test to insert by name
                             EasyInsert().add("a", 1, true).add("b", 2, true).add("c", 3, true),
                             EasyInsert().add("a", 1, true).add("b", 2, true).add("a", 3, false),
                             EasyInsert().add("a", 1, true).add("b", 2, true).add("b", 3, false),
                             EasyInsert().add("a", 1, true).add("b", 2, true).add("a", 2, false),
                             EasyInsert().add("a", 1, true).add("b", 2, true).add("b", 1, false),
                             EasyInsert().add("a", 1, true).add("b", 2, true).add("c", 1, false),
                             EasyInsert().add("a", 1, true).add("b", 2, true).add("c", 1, false).add("c", 3, true),
                             EasyInsert().add("a", 1, true).add("b", 2, true).add("c", 2, false),
                             EasyInsert().add("a", 1, true).add("b", 2, true).add("b", 3, false).add("c", 3, true)
                             // end
                             ));

/************************************************
 *      Test the order iterator by priority.
 ************************************************/
using ItByPriorityT = std::vector<EntryTest>;
using ItTest = ::testing::TestWithParam<ItByPriorityT>;

class EasyIt
{
private:
    ItByPriorityT m_arrayEntry;

public:
    EasyIt() = default;

    EasyIt& add(std::string name, std::size_t priority)
    {
        m_arrayEntry.push_back({std::move(name), priority});
        return *this;
    }

    // Cast EasyIt to ItByPriorityT
    operator ItByPriorityT() const { return m_arrayEntry; }
};

TEST_P(ItTest, It)
{
    auto& arrayTest = GetParam();

    // Insert disordered array
    ri::Table<ValueType> table;
    for (auto& entry : arrayTest)
    {
        EXPECT_EQ(table.insert(entry.name, entry.priority, ValueType(entry.value)), true);
        checkEntryTable(table, entry, true);
    }

    ASSERT_TRUE(table.size() == arrayTest.size());
    ASSERT_FALSE(table.empty());

    // Sort the array by priority
    auto sortArray = arrayTest;
    std::sort(sortArray.begin(),
              sortArray.end(),
              [](const EntryTest& lhs, const EntryTest& rhs) { return lhs.priority > rhs.priority; });

    // Check if the iterator return the entries in the right order (Higher priority first)
    std::size_t indexSorted = 0;

    // Check reference
    for (auto& entry : table)
    {
        EXPECT_EQ(entry, sortArray[indexSorted++].value);
    }

    // Check const reference
    indexSorted = 0;
    for (const auto& entry : table)
    {
        EXPECT_EQ(entry, sortArray[indexSorted++].value);
    }

    // Check iterator
    indexSorted = 0;
    for (auto it = table.begin(); it != table.end(); ++it)
    {
        EXPECT_EQ(*it, sortArray[indexSorted++].value);
    }

    // Check const iterator
    indexSorted = 0;
    for (auto it = table.cbegin(); it != table.cend(); ++it)
    {
        EXPECT_EQ(*it, sortArray[indexSorted++].value);
    }
}

INSTANTIATE_TEST_SUITE_P(Table,
                         ItTest,
                         ::testing::Values(
                             // Test to insert by name
                             EasyIt().add("a", 1).add("b", 2).add("c", 3),
                             EasyIt().add("a", 3).add("b", 2).add("c", 1),
                             EasyIt().add("a", 1).add("b", 3).add("c", 2),
                             EasyIt().add("a", 3).add("b", 1).add("c", 2),
                             EasyIt().add("a", 2).add("b", 1).add("c", 3),
                             EasyIt().add("a", 2).add("b", 3).add("c", 1),
                             EasyIt().add("a", 1).add("b", 2).add("c", 3).add("d", 4),
                             EasyIt().add("a", 1).add("b", 2).add("c", 3).add("d", 4).add("e", 5),
                             EasyIt().add("a", 1).add("b", 2).add("c", 3).add("d", 4).add("e", 5).add("f", 6),
                             EasyIt().add("a", 6).add("b", 5).add("c", 4).add("d", 3).add("e", 2).add("f", 1),
                             EasyIt().add("a", 5).add("b", 44).add("c", 33).add("d", 55).add("e", 110).add("f", 90)
                             // end
                             ));

/************************************************
 *      Test Set/Get priority by name.
 ************************************************/

std::vector<EntryTest> g_initStatePrior = {
    {"a", 1, "a"},
    {"b", 2, "b"},
    {"c", 3, "c"},
    {"d", 4, "d"},
    {"e", 5, "e"},
    {"f", 6, "f"},
    {"h", 10, "h"},
    {"i", 15, "i"},
    {"j", 18, "j"},
    {"k", 20, "k"}
};

/**
 * @brief Check if the priority is the same as the expected.
 * std::string name, std::size_t newPriority, bool expected result
 */
using PriorityT = std::tuple<std::string, std::size_t, bool>;
using PriorityTest = ::testing::TestWithParam<PriorityT>;

class EasySet
{
private:
    PriorityT m_priority;

public:
    EasySet(std::string name, std::size_t newPriority, bool expected)
    {
        m_priority = std::make_tuple(std::move(name), newPriority, expected);
    }

    // Cast EasySet to PriorityT
    operator PriorityT() const { return m_priority; }
};

TEST_P(PriorityTest, Priority)
{
    auto& [name, newPriority, expected] = GetParam();
    ri::Table<ValueType> table;
    // Insert all entries (And check if the insert is ok)
    for (auto& entry : g_initStatePrior)
    {
        EXPECT_EQ(table.insert(entry.name, entry.priority, ValueType(entry.value)), true);
        checkEntryTable(table, entry, true);
    }

    ASSERT_TRUE(table.size() == g_initStatePrior.size());
    ASSERT_FALSE(table.empty());

    // Check if the priority is the same as the expected
    EXPECT_EQ(table.setPriority(name, newPriority), expected);
    if (expected)
    {
        // Check if the name and priority exists
        EXPECT_TRUE(table.nameExists(name));
        EXPECT_TRUE(table.priorityExists(newPriority));

        // Check if the name and the priority is the same entry
        const auto& value = table.get(name);
        EXPECT_EQ(value, ValueType(name));
    }
    else
    {
        // Check if the name doesn't exists or the priority is already used
        EXPECT_TRUE(!table.nameExists(name) || table.priorityExists(newPriority));
    }
}

INSTANTIATE_TEST_SUITE_P(Table,
                         PriorityTest,
                         ::testing::Values(
                             // Test to insert by name
                             EasySet("a", 1, true),
                             EasySet("a", 2, false),
                             EasySet("a", 3, false),
                             EasySet("a", 7, true),
                             EasySet("z", 1, false),
                             EasySet("z", 2, false),
                             EasySet("z", 3, false),
                             EasySet("z", 7, false)
                             // end
                             ));


/************************************************
 *     Test Erase by name
 ************************************************/
TEST(Table, erase) {

    // Insert all entries (And check if the insert is ok)
    ri::Table<ValueType> table;
    for (auto& entry : g_initStatePrior)
    {
        EXPECT_EQ(table.insert(entry.name, entry.priority, ValueType(entry.value)), true);
        checkEntryTable(table, entry, true);
    }

    ASSERT_TRUE(table.size() == g_initStatePrior.size());

    // Erase all entries
    for (auto& entry : g_initStatePrior)
    {
        EXPECT_EQ(table.erase(entry.name), true);
        ASSERT_FALSE(table.nameExists(entry.name));
        ASSERT_FALSE(table.priorityExists(entry.priority));
    }

    ASSERT_TRUE(table.empty());
}

/************************************************
 *     Modify the entry by reference
 ************************************************/
TEST(Table, modify) {

    // Insert all entries (And check if the insert is ok)
    ri::Table<ValueType> table;
    for (auto& entry : g_initStatePrior)
    {
        EXPECT_EQ(table.insert(entry.name, entry.priority, ValueType(entry.value)), true);
        checkEntryTable(table, entry, true);
    }

    ASSERT_TRUE(table.size() == g_initStatePrior.size());

    // Modify all entries
    for (auto& entry : g_initStatePrior)
    {
        auto& value = table.get(entry.name);
        value += "modified";
        EXPECT_EQ(table.get(entry.name), ValueType(entry.value + "modified"));
    }
}

/************************************************
 *     Test Get priority by range
 ************************************************/
using MaxPriorityT = std::tuple<std::size_t, std::size_t, std::size_t, bool>;
using MaxPriorityTest = ::testing::TestWithParam<MaxPriorityT>;

class EasyGetMaxPriorityT
{
private:
    MaxPriorityT m_getMaxPriorityT;
public:
    EasyGetMaxPriorityT(std::size_t min, std::size_t max, std::size_t priority, bool exception)
    {
        m_getMaxPriorityT = std::make_tuple(min, max, priority, exception);
    }

    operator MaxPriorityT() const {return m_getMaxPriorityT; };
};

TEST_P(MaxPriorityTest, Functionallity)
{
    // Insert all entries (And check if the insert is ok)
    ri::Table<ValueType> table;
    for (auto& entry : g_initStatePrior)
    {
        EXPECT_EQ(table.insert(entry.name, entry.priority, ValueType(entry.value)), true);
        checkEntryTable(table, entry, true);
    }

    auto &[minP, maxP, lowestPriority, exception] = GetParam();

    if (exception)
    {
        EXPECT_ANY_THROW(table.getBiggestFreePriority(minP, maxP));
    }
    else
    {
        EXPECT_EQ(table.getBiggestFreePriority(minP, maxP), lowestPriority);
    }
}

INSTANTIATE_TEST_SUITE_P(Table,
                         MaxPriorityTest,
                         ::testing::Values(
                             // Test to insert by name
                             MaxPriorityT(6, 1, 1, true),
                             MaxPriorityT(15, 15, 15, true),
                             MaxPriorityT(15, 20, 15, true),
                             MaxPriorityT(20, 10, 11, false),
                             MaxPriorityT(20, 15, 16, false),
                             MaxPriorityT(20, 1, 7, false)
                             // end
                             ));
