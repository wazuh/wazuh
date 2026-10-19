#include <sca_reason_sanitizer.hpp>

#include <string_view>

namespace
{
    /// @brief Ends a reason that had to be cut, on a line of its own.
    constexpr std::string_view TRUNCATION_MARKER {"\n[truncated]"};

    /// @brief Length of the UTF-8 sequence a lead byte starts, and the range allowed for the byte
    ///        after it. A length of 0 means the byte cannot start a sequence.
    struct SequenceShape
    {
        size_t length = 0;
        unsigned char secondMin = 0x80;
        unsigned char secondMax = 0xBF;
    };

    SequenceShape ShapeOf(const unsigned char lead)
    {
        // RFC 3629 narrows the byte after the lead for four lead values, which is what rules
        // out overlong encodings, UTF-16 surrogate halves and code points above U+10FFFF.
        // Counting continuation bytes alone accepts all three, and json::dump() rejects them.
        if (lead < 0x80)
        {
            return {1};
        }

        if (lead >= 0xC2 && lead <= 0xDF)
        {
            return {2};
        }

        if ((lead & 0xF0) == 0xE0)
        {
            return {3, static_cast<unsigned char>(lead == 0xE0 ? 0xA0 : 0x80), static_cast<unsigned char>(lead == 0xED ? 0x9F : 0xBF)};
        }

        if (lead >= 0xF0 && lead <= 0xF4)
        {
            return {4, static_cast<unsigned char>(lead == 0xF0 ? 0x90 : 0x80), static_cast<unsigned char>(lead == 0xF4 ? 0x8F : 0xBF)};
        }

        return {};
    }

    /// @brief Length of the valid UTF-8 sequence starting at index, or 0 when there is none.
    size_t ValidSequenceLength(const std::string& text, const size_t index)
    {
        const auto shape = ShapeOf(static_cast<unsigned char>(text[index]));

        if (shape.length == 0 || index + shape.length > text.size())
        {
            return 0;
        }

        for (size_t offset = 1; offset < shape.length; ++offset)
        {
            const auto byte = static_cast<unsigned char>(text[index + offset]);
            const auto low = (offset == 1) ? shape.secondMin : static_cast<unsigned char>(0x80);
            const auto high = (offset == 1) ? shape.secondMax : static_cast<unsigned char>(0xBF);

            if (byte < low || byte > high)
            {
                return 0;
            }
        }

        return shape.length;
    }

    /// @brief Copies text, replacing each byte that is not part of a valid UTF-8 sequence with '?'.
    std::string ReplaceInvalidUtf8(const std::string& text)
    {
        std::string valid;
        valid.reserve(text.size());

        for (size_t index = 0; index < text.size();)
        {
            const auto length = ValidSequenceLength(text, index);

            if (length == 0)
            {
                valid.push_back('?');
                ++index;
                continue;
            }

            valid.append(text, index, length);
            index += length;
        }

        return valid;
    }

    /// @brief Cuts valid UTF-8 text longer than maxLength to at most maxLength bytes outside a
    ///        multibyte sequence, dropping any line break the cut leaves at the end.
    std::string CutAtCharacter(const std::string& text, const size_t maxLength)
    {
        size_t end = maxLength;

        while (end > 0 && (static_cast<unsigned char>(text[end]) & 0xC0) == 0x80)
        {
            --end;
        }

        while (end > 0 && text[end - 1] == '\n')
        {
            --end;
        }

        return text.substr(0, end);
    }

    /// @brief Cuts valid UTF-8 text longer than maxLength to at most maxLength bytes: at its last line
    ///        break within the limit when that keeps more than the first line, else inside a line.
    std::string CutToFit(const std::string& text, const size_t maxLength)
    {
        // The first line alone is not enough: in a Failed reason it is the header, which names no rule
        const auto lastLine = text.rfind('\n', maxLength);

        if (lastLine != std::string::npos && lastLine != text.find('\n'))
        {
            return text.substr(0, lastLine);
        }

        return CutAtCharacter(text, maxLength);
    }
} // namespace

namespace sca
{
    std::string SanitizeReason(const std::string& reason, const size_t maxLength)
    {
        const auto valid = ReplaceInvalidUtf8(reason);

        if (valid.size() <= maxLength)
        {
            return valid;
        }

        // The marker counts inside the cap; a cap too small to hold it gets a plain cut
        if (maxLength <= TRUNCATION_MARKER.size())
        {
            return CutToFit(valid, maxLength);
        }

        auto cut = CutToFit(valid, maxLength - TRUNCATION_MARKER.size());
        cut += TRUNCATION_MARKER;
        return cut;
    }
} // namespace sca
