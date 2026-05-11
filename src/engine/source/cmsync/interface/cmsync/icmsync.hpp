#ifndef _CMSYNC_ICMSYNC
#define _CMSYNC_ICMSYNC

#include <string>
#include <vector>


namespace cm::sync
{

class ICMSync {
public:
    virtual ~ICMSync() = default;

    /**
     * @brief Request graceful shutdown of in-flight synchronization operations.
     * Idempotent and thread-safe. After calling this, ongoing synchronize() calls
     * will abort at the next checkpoint and return early.
     */
    virtual void requestShutdown() = 0;
};

} // namespace cm::sync

#endif // _CMSYNC_ICMSYNC
