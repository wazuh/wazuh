#include <sca_reason_sanitizer.hpp>

namespace sca
{
    std::string SanitizeReason(const std::string& reason, const size_t maxLength)
    {
        // Replace whatever is not valid UTF-8, one '?' per offending byte.
        std::string valid;
        valid.reserve(reason.size());

        for (size_t index = 0; index < reason.size();)
        {
            const auto lead = static_cast<unsigned char>(reason[index]);
            size_t sequenceLength = 0;

            // RFC 3629 narrows the byte after the lead for four lead values, which is what rules
            // out overlong encodings, UTF-16 surrogate halves and code points above U+10FFFF.
            // Counting continuation bytes alone accepts all three, and json::dump() rejects them.
            unsigned char secondMin = 0x80;
            unsigned char secondMax = 0xBF;

            if (lead < 0x80)
            {
                sequenceLength = 1;
            }
            else if (lead >= 0xC2 && lead <= 0xDF)
            {
                sequenceLength = 2;
            }
            else if ((lead & 0xF0) == 0xE0)
            {
                sequenceLength = 3;

                if (lead == 0xE0)
                {
                    secondMin = 0xA0;
                }
                else if (lead == 0xED)
                {
                    secondMax = 0x9F;
                }
            }
            else if (lead >= 0xF0 && lead <= 0xF4)
            {
                sequenceLength = 4;

                if (lead == 0xF0)
                {
                    secondMin = 0x90;
                }
                else if (lead == 0xF4)
                {
                    secondMax = 0x8F;
                }
            }

            bool complete = sequenceLength != 0 && index + sequenceLength <= reason.size();

            for (size_t offset = 1; complete && offset < sequenceLength; ++offset)
            {
                const auto continuation = static_cast<unsigned char>(reason[index + offset]);
                const unsigned char low = (offset == 1) ? secondMin : static_cast<unsigned char>(0x80);
                const unsigned char high = (offset == 1) ? secondMax : static_cast<unsigned char>(0xBF);
                complete = continuation >= low && continuation <= high;
            }

            if (complete)
            {
                valid.append(reason, index, sequenceLength);
                index += sequenceLength;
            }
            else
            {
                valid.push_back('?');
                ++index;
            }
        }

        if (valid.size() <= maxLength)
        {
            return valid;
        }

        const auto lastLine = valid.rfind('\n', maxLength);

        if (lastLine != std::string::npos)
        {
            return valid.substr(0, lastLine);
        }

        size_t end = maxLength;

        while (end > 0 && (static_cast<unsigned char>(valid[end]) & 0xC0) == 0x80)
        {
            --end;
        }

        return valid.substr(0, end);
    }
} // namespace sca
