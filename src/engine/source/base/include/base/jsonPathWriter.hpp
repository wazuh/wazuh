// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef _BASE_JSON_PATH_WRITER_HPP
#define _BASE_JSON_PATH_WRITER_HPP

#include <cstddef>
#include <optional>
#include <set>
#include <string_view>
#include <unordered_map>

#include <rapidjson/document.h>
#include <rapidjson/pointer.h>

#include <base/json.hpp>

namespace json
{

/**
 * @brief Scoped writer over a Json document for code that builds wide objects member by member.
 *
 * Every operation gives exactly the result of the Json method of the same name: same document, same return value
 * and same exception. The only difference is how a member is looked up inside an object: Json scans the members
 * of the object on every call, so writing N members into one object costs O(N^2) name comparisons; the writer
 * keeps an ordered index (name -> position) for each object that has more than `indexThreshold` members, so the
 * same N writes or lookups cost O(N log N) whatever the member names are. Objects at or below the threshold are
 * scanned exactly like Json does, and constructing a writer allocates nothing.
 *
 * The index of an object is built the first time the writer looks a member up in it while it is above the threshold
 * (reads included), which costs more than the single scan Json would do: a writer pays off when it is kept for the
 * whole construction of a document, not when it is created for one or two operations on an existing wide object.
 * Index entries live until the writer is destroyed. The error paths of size() (missing path, value without a
 * size) are resolved by Json and scan like Json does.
 *
 * Rules of use:
 *  - While the writer is alive, the document is modified only through it, and no member is erased or reordered.
 *    Reading the document directly stays valid, but only reads made through the writer use the index.
 *  - The Json outlives the writer and is neither moved nor assigned while the writer is alive.
 *  - A writer is not shared between threads.
 *  - The result of an operation is the result of the Json method of the same name; if in doubt, Json is the
 *    reference.
 *  - A value written through the writer is never the target document itself.
 */
class PathWriter final
{
public:
    /// Objects with more members than this are looked up through the index.
    static constexpr size_t DEFAULT_INDEX_THRESHOLD = 128;

    /**
     * @brief Create a writer over a document.
     *
     * @param doc Document to read and modify. Must outlive the writer.
     * @param indexThreshold Number of members above which an object is indexed.
     */
    explicit PathWriter(Json& doc, size_t indexThreshold = DEFAULT_INDEX_THRESHOLD);
    ~PathWriter();

    PathWriter(const PathWriter&) = delete;
    PathWriter& operator=(const PathWriter&) = delete;
    PathWriter(PathWriter&&) = delete;
    PathWriter& operator=(PathWriter&&) = delete;

    /// @brief Same as Json::set(pointerPath, value).
    void set(std::string_view pointerPath, const Json& value);
    /// @brief Same as Json::setString(value, path).
    void setString(std::string_view value, std::string_view path = "");
    /// @brief Same as Json::setStringAsMembers(value, path).
    void setStringAsMembers(std::string_view value, std::string_view path);
    /// @brief Same as Json::setNullAsMembers(path).
    void setNullAsMembers(std::string_view path);
    /// @brief Same as Json::setObject(path).
    void setObject(std::string_view path = "");
    /// @brief Same as Json::setArray(path).
    void setArray(std::string_view path = "");
    /// @brief Same as Json::appendString(value, path).
    void appendString(std::string_view value, std::string_view path = "");
    /// @brief Same as Json::appendJson(value, path).
    void appendJson(const Json& value, std::string_view path = "");

    /// @brief Same as Json::exists(pointerPath).
    bool exists(std::string_view pointerPath) const;
    /// @brief Same as Json::isObject(path).
    bool isObject(std::string_view path = "") const;
    /// @brief Same as Json::isArray(path).
    bool isArray(std::string_view path = "") const;
    /// @brief Same as Json::size(path).
    size_t size(std::string_view path = "") const;
    /// @brief Same as Json::getJson(path).
    std::optional<Json> getJson(std::string_view path = "") const;

    /// @brief Number of index entries currently held by the writer (diagnostics and tests).
    size_t indexedObjects() const;

private:
    using Value = rapidjson::Value;
    using Member = rapidjson::Value::Member;
    using Token = rapidjson::Pointer::Token;
    using Position = rapidjson::SizeType;

    struct IndexEntry;

    /// Orders member positions by the name they hold in the live member array of the entry (bytes, then length).
    struct NameLess
    {
        using is_transparent = void;

        const IndexEntry* entry;

        bool operator()(Position lhs, Position rhs) const;
        bool operator()(Position lhs, std::string_view rhs) const;
        bool operator()(std::string_view lhs, Position rhs) const;
    };

    /// Index of one object: the positions of its members, first occurrence of each name only.
    struct IndexEntry
    {
        const Member* base;                     ///< Member array of the object; the comparator reads names through it.
        size_t indexed;                         ///< Number of members indexed so far (duplicates included).
        std::set<Position, NameLess> positions; ///< Positions ordered by name.

        explicit IndexEntry(const Member* members)
            : base(members)
            , indexed(0)
            , positions(NameLess {this})
        {
        }

        IndexEntry(const IndexEntry&) = delete;
        IndexEntry& operator=(const IndexEntry&) = delete;
        IndexEntry(IndexEntry&&) = delete;
        IndexEntry& operator=(IndexEntry&&) = delete;
    };

    /// Result of looking a name up in an object: the member (null if absent) and the entry (null if not indexed).
    struct Lookup
    {
        Member* member;
        IndexEntry* entry;
    };

    Lookup findMember(Value& object, const Token& token) const;
    Value& addMember(Value& object, IndexEntry* entry, const Token& token);
    Value& create(const Token* begin, const Token* end);
    Value* get(const Token* begin, const Token* end) const;
    void forget(const Value& target);

    Json& m_doc;
    size_t m_indexThreshold;
    /// Entries keyed by the address of the member array of the indexed object.
    mutable std::unordered_map<const Member*, IndexEntry> m_index;
};

} // namespace json

#endif // _BASE_JSON_PATH_WRITER_HPP
