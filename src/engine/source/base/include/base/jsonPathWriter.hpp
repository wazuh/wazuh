// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef _BASE_JSON_PATH_WRITER_HPP
#define _BASE_JSON_PATH_WRITER_HPP

#include <cstddef>
#include <functional>
#include <limits>
#include <new>
#include <optional>
#include <set>
#include <string_view>
#include <unordered_map>
#include <utility>

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
 *
 * Anchors. An operation that takes a path resolves it from the root of the document on every call, so its cost grows
 * with the length of the path. Code that walks a tree and writes under the node it is visiting can resolve that node
 * once, keep it as an Anchor, and pass paths relative to it: the overloads that take an Anchor run the same code as
 * the ones that take an absolute path, starting at the anchored node instead of at the root.
 *
 * Guarantee: for an anchor that names the node of absolute path A and a valid relative path R, `op(anchor, R)` leaves
 * the same document, returns the same value and throws the same exception type as `op(A + R)`, with A written as a
 * plain JSON pointer ("/a/b"), not in the URI fragment form ("#/a/b"), where a '%' in R would be read as an escape.
 *
 * A relative path is valid when it is empty (the anchored node itself) or starts with '/' and is a valid JSON
 * pointer. The URI fragment form ("#/a") is not valid here. Every overload that takes an anchor, the reads included,
 * throws std::runtime_error on an invalid relative path.
 *
 * An anchor is used only with the writer that created it, and only while that writer is alive: every overload that
 * takes an anchor throws std::runtime_error, before reading or changing anything, if the anchor was created by another
 * live writer. A writer is told apart by its address, so an anchor that outlives its writer is not detected (rule 4).
 *
 * Validity of an anchor over time (the caller's responsibility; the writer does not check it):
 *  1. An anchor is valid while the immediate container of its node does not reallocate. It stops being valid when a
 *     member is added to the parent object, an element is appended to the parent array, the parent changes type (a
 *     write through it turns an array into an object, or the reverse, and destroys its elements), or an ancestor is
 *     overwritten. Writing inside the anchored node (adding members to it, turning it into an object or an array in
 *     place) does not invalidate it.
 *  2. The anchor of the root is valid for as long as the writer lives.
 *  3. After wrapInArray, an anchor to the wrapped node is still valid and names the same path, which now holds the
 *     array; anchors to its former descendants point to live memory but name the path below element 0.
 *  4. No anchor is valid after the writer that created it is destroyed.
 * Using an anchor after it stopped being valid is not supported and has no guaranteed outcome: the write may be lost
 * or may land in the live document.
 *
 * Allocation failures. When an allocation fails, every write (set*, append*, ensure, wrapInArray, by absolute path or
 * by anchor) throws std::bad_alloc and leaves the document exactly as it was, and the writer stays usable. A write
 * first reads the part of the path that exists, then builds apart everything it needs (the missing levels around the
 * new value, a deep copy of a Json, the array that replaces a scalar or wraps a node), and only then attaches it with
 * one operation that reallocates before it touches the document (AddMember, Reserve + PushBack) or with a move that
 * cannot fail. The index allocates on the throwing base allocator of the documents: building or rebuilding the entry of
 * an object happens while reading, and an entry whose construction fails is erased before the exception propagates;
 * updating an entry after a member was attached cannot fail the write, the entry is dropped instead and rebuilt by the
 * next lookup. An entry that can still be matched is either exact (current member array, valid positions, first
 * occurrence of a duplicated name) or absent. Anchors that were valid before a failed write stay valid.
 */
class PathWriter final
{
public:
    /// Objects with more members than this are looked up through the index.
    static constexpr size_t DEFAULT_INDEX_THRESHOLD = 128;

    /**
     * @brief A node of the document that has already been resolved.
     *
     * Opaque, copyable and small. Only the writer creates one: root(), find() and ensure(); it is used only with the
     * writer that created it. See the class description for how long it stays valid.
     */
    class Anchor final
    {
    public:
        /// @brief Two anchors are equal when they name the same node address.
        friend bool operator==(const Anchor& lhs, const Anchor& rhs) { return lhs.m_value == rhs.m_value; }
        friend bool operator!=(const Anchor& lhs, const Anchor& rhs) { return !(lhs == rhs); }

    private:
        friend class PathWriter;
        Anchor(const PathWriter* owner, json::Value* value)
            : m_owner(owner)
            , m_value(value)
        {
        }

        /// Writer that created the anchor; the anchored overloads reject an anchor whose owner is another writer.
        const PathWriter* m_owner;
        json::Value* m_value;
    };

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

    /// @brief Anchor of the root of the document.
    Anchor root();

    /**
     * @brief Resolve a path relative to an anchor without creating anything.
     *
     * @param from Anchor the path is relative to.
     * @param relPath Relative path; empty names the anchored node itself.
     * @return The anchor of the node, or std::nullopt if the path does not exist.
     * @throw std::runtime_error If the relative path is not valid.
     */
    std::optional<Anchor> find(Anchor from, std::string_view relPath) const;

    /**
     * @brief Resolve a path relative to an anchor, creating the node and whatever is missing on the way.
     *
     * Creates exactly what a write to that path would create. The target node is not touched if it already exists
     * (the nodes on the way, the anchored one included, are converted as a write would convert them); a new node is
     * null until something is written into it.
     *
     * @param from Anchor the path is relative to.
     * @param relPath Relative path; empty names the anchored node itself.
     * @return The anchor of the node.
     * @throw std::runtime_error If the relative path is not valid.
     */
    Anchor ensure(Anchor from, std::string_view relPath);

    /// @brief Same as setString(value, path), with the path relative to an anchor.
    void setString(Anchor from, std::string_view value, std::string_view relPath);
    /// @brief Same as setObject(path), with the path relative to an anchor.
    void setObject(Anchor from, std::string_view relPath = "");
    /// @brief Same as appendString(value, path), with the path relative to an anchor.
    void appendString(Anchor from, std::string_view value, std::string_view relPath = "");
    /// @brief Same as appendJson(value, path), with the path relative to an anchor.
    void appendJson(Anchor from, const Json& value, std::string_view relPath = "");
    /// @brief Same as exists(pointerPath), with the path relative to an anchor.
    bool exists(Anchor from, std::string_view relPath) const;
    /// @brief Same as isObject(path), with the path relative to an anchor.
    bool isObject(Anchor from, std::string_view relPath = "") const;
    /// @brief Same as isArray(path), with the path relative to an anchor.
    bool isArray(Anchor from, std::string_view relPath = "") const;
    /**
     * @brief Same as size(path), with the path relative to an anchor.
     *
     * @throw std::runtime_error If the path does not exist or its value has no size.
     */
    size_t size(Anchor from, std::string_view relPath = "") const;

    /**
     * @brief Replace a value by an array whose only element is that value, without copying it.
     *
     * Same document as getJson() + setArray() + appendJson() on that path, in constant time: the value is moved, and
     * an object that was indexed keeps its index entry.
     *
     * @param from Anchor the path is relative to.
     * @param relPath Relative path; empty names the anchored node itself.
     * @return false, leaving the document untouched, if the path does not exist.
     * @throw std::runtime_error If the relative path is not valid.
     */
    bool wrapInArray(Anchor from, std::string_view relPath = "");

    /// @brief Number of index entries currently held by the writer (diagnostics and tests).
    size_t indexedObjects() const;

private:
    using Value = json::Value;
    using Member = json::Value::Member;
    using Token = json::Pointer::Token;
    using Position = rapidjson::SizeType;

    struct IndexEntry;

    /**
     * Containers of the index allocate on the base allocator of the documents, which throws std::bad_alloc (and so
     * honours its test hook). A stateless adapter: rapidjson::StdAllocator is not assignable, which node handles need.
     */
    template<typename T>
    struct IndexAllocator
    {
        using value_type = T;

        IndexAllocator() noexcept = default;
        template<typename U>
        IndexAllocator(const IndexAllocator<U>& /*other*/) noexcept
        {
        }

        T* allocate(std::size_t n)
        {
            if (n > std::numeric_limits<std::size_t>::max() / sizeof(T))
            {
                throw std::bad_alloc();
            }
            return static_cast<T*>(json::baseAllocator().Malloc(n * sizeof(T)));
        }

        void deallocate(T* block, std::size_t /*n*/) noexcept { json::BaseAllocator::Free(block); }

        friend bool operator==(const IndexAllocator& /*lhs*/, const IndexAllocator& /*rhs*/) noexcept { return true; }
        friend bool operator!=(const IndexAllocator& /*lhs*/, const IndexAllocator& /*rhs*/) noexcept { return false; }
    };

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
        const Member* base; ///< Member array of the object; the comparator reads names through it.
        size_t indexed;     ///< Number of members indexed so far (duplicates included).
        std::set<Position, NameLess, IndexAllocator<Position>> positions; ///< Positions ordered by name.

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

    /**
     * @brief Node named by an anchor, checking that the anchor was created by this writer.
     *
     * Every overload that takes an anchor calls it first, before reading or changing anything.
     *
     * @param from Anchor to resolve.
     * @return The anchored node.
     * @throw std::runtime_error If the anchor was created by another live writer.
     */
    Value& resolve(Anchor from) const;

    Lookup findMember(Value& object, const Token& token) const;
    /// Index maintenance after writeAt added a member to `object` whose name `lookup` did not find; never throws.
    void memberAdded(const Value& object, const Lookup& lookup) noexcept;
    /// Write `leaf` (or ensure the node when null) at the path from `from`; returns the target, already attached.
    Value& write(Value& from, const Token* begin, const Token* end, Value* leaf);
    Value* get(Value& from, const Token* begin, const Token* end) const;
    void forget(const Value& target) noexcept;

    // One body per operation that has a relative overload: the absolute overload calls it with the root of the
    // document, the relative one with the anchored node
    void setStringAt(Value& from, const json::Pointer& pointer, std::string_view value);
    void setObjectAt(Value& from, const json::Pointer& pointer);
    /// Append `element` (moved) to the array at the path, or write [element] there if the path holds no array.
    void appendValueAt(Value& from, const json::Pointer& pointer, Value& element);
    void appendStringAt(Value& from, const json::Pointer& pointer, std::string_view value);
    void appendJsonAt(Value& from, const json::Pointer& pointer, const Json& value);
    bool existsAt(Value& from, const json::Pointer& pointer) const;
    bool isObjectAt(Value& from, const json::Pointer& pointer) const;
    bool isArrayAt(Value& from, const json::Pointer& pointer) const;
    /// std::nullopt when the path does not exist or its value has no size.
    std::optional<size_t> sizeAt(Value& from, const json::Pointer& pointer) const;

    Json& m_doc;
    size_t m_indexThreshold;
    /// Entries keyed by the address of the member array of the indexed object.
    mutable std::unordered_map<const Member*,
                               IndexEntry,
                               std::hash<const Member*>,
                               std::equal_to<const Member*>,
                               IndexAllocator<std::pair<const Member* const, IndexEntry>>>
        m_index;
};

} // namespace json

#endif // _BASE_JSON_PATH_WRITER_HPP
