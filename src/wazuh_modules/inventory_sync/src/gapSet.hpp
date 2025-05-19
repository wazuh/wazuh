#include <chrono>
#include <cstdint>
#include <vector>

class GapSet final
{
public:
    explicit GapSet(const uint64_t size)
        : m_size(size)
        , m_gaps(size, false)
    {
    }

    void observe(const uint64_t seq)
    {
        if (seq >= m_size || m_gaps[seq])
        {
            return;
        }

        m_lastUpdate = std::chrono::steady_clock::now();
        m_gaps[seq] = true;
        ++m_observedCount;
    }

    bool empty() const
    {
        return m_observedCount == m_size;
    }

    bool contains(const uint64_t seq) const
    {
        if (seq >= m_size)
        {
            return false;
        }

        return m_gaps[seq];
    }
    std::vector<std::pair<uint64_t, uint64_t>> ranges() const
    {
        std::vector<std::pair<uint64_t, uint64_t>> result;

        bool inGap = false;
        uint64_t gapStart = 0;

        for (uint64_t i = 0; i < m_size; ++i)
        {
            if (!m_gaps[i])
            {
                if (!inGap)
                {
                    inGap = true;
                    gapStart = i;
                }
            }
            else
            {
                if (inGap)
                {
                    result.emplace_back(gapStart, i - 1);
                    inGap = false;
                }
            }
        }

        if (inGap)
        {
            result.emplace_back(gapStart, m_size - 1);
        }

        return result;
    }

private:
    uint64_t m_size {0};
    std::vector<bool> m_gaps;
    uint64_t m_observedCount {0};
    std::chrono::time_point<std::chrono::steady_clock> m_lastUpdate;
};
