
#ifndef _WDB_DBSYNC_H
#define _WDB_DBSYNC_H

#include <baseTypes.hpp>
#include <json.hpp>

namespace wazuhdb::dbsync
{

bool dbSync(base::Event e);

}

#endif // _WDB_DBSYNC_H
