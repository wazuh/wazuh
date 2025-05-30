constexpr auto OS_SQL_STATEMENT
{
    R"(CREATE TABLE dbsync_osinfo (
    hostname TEXT,
    architecture TEXT,
    os_name TEXT,
    os_version TEXT,
    os_codename TEXT,
    os_major TEXT,
    os_minor TEXT,
    os_patch TEXT,
    os_build TEXT,
    os_platform TEXT,
    sysname TEXT,
    release TEXT,
    version TEXT,
    os_release TEXT,
    os_display_version TEXT,
    checksum TEXT,
    PRIMARY KEY (os_name)) WITHOUT ROWID;)"
};

constexpr auto OS_SYNC_CONFIG_STATEMENT
{
    R"(
    {
        "decoder_type":"JSON_RANGE",
        "table":"dbsync_osinfo",
        "component":"syscollector_osinfo",
        "index":"os_name",
        "checksum_field":"checksum",
        "no_data_query_json": {
                "row_filter":"WHERE os_name BETWEEN '?' and '?' ORDER BY os_name",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "count_range_query_json": {
                "row_filter":"WHERE os_name BETWEEN '?' and '?' ORDER BY os_name",
                "count_field_name":"count",
                "column_list":["count(*) AS count "],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "row_data_query_json": {
                "row_filter":"WHERE os_name ='?'",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "range_checksum_query_json": {
                "row_filter":"WHERE os_name BETWEEN '?' and '?' ORDER BY os_name",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        }
    }
    )"
};

constexpr auto OS_START_CONFIG_STATEMENT
{
    R"({"table":"dbsync_osinfo",
        "first_query":
            {
                "column_list":["os_name"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"os_name DESC",
                "count_opt":1
            },
        "last_query":
            {
                "column_list":["os_name"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"os_name ASC",
                "count_opt":1
            },
        "component":"syscollector_osinfo",
        "index":"os_name",
        "last_event":"last_event",
        "checksum_field":"checksum",
        "range_checksum_query_json":
            {
                "row_filter":"WHERE os_name BETWEEN '?' and '?' ORDER BY os_name",
                "column_list":["os_name, checksum"],
                "distinct_opt":false,
                "order_by_opt":"",
                "count_opt":100
            }
        })"
};

constexpr auto HW_SQL_STATEMENT
{
    R"(CREATE TABLE dbsync_hwinfo (
    board_serial TEXT,
    cpu_name TEXT,
    cpu_cores INTEGER,
    cpu_mhz DOUBLE,
    ram_total INTEGER,
    ram_free INTEGER,
    ram_usage INTEGER,
    checksum TEXT,
    PRIMARY KEY (board_serial)) WITHOUT ROWID;)"
};

constexpr auto HW_SYNC_CONFIG_STATEMENT
{
    R"(
    {
        "decoder_type":"JSON_RANGE",
        "table":"dbsync_hwinfo",
        "component":"syscollector_hwinfo",
        "index":"board_serial",
        "checksum_field":"checksum",
        "no_data_query_json": {
                "row_filter":"WHERE board_serial BETWEEN '?' and '?' ORDER BY board_serial",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "count_range_query_json": {
                "row_filter":"WHERE board_serial BETWEEN '?' and '?' ORDER BY board_serial",
                "count_field_name":"count",
                "column_list":["count(*) AS count "],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "row_data_query_json": {
                "row_filter":"WHERE board_serial ='?'",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "range_checksum_query_json": {
                "row_filter":"WHERE board_serial BETWEEN '?' and '?' ORDER BY board_serial",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        }
    }
    )"
};

constexpr auto HW_START_CONFIG_STATEMENT
{
    R"({"table":"dbsync_hwinfo",
        "first_query":
            {
                "column_list":["board_serial"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"board_serial DESC",
                "count_opt":1
            },
        "last_query":
            {
                "column_list":["board_serial"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"board_serial ASC",
                "count_opt":1
            },
        "component":"syscollector_hwinfo",
        "index":"board_serial",
        "last_event":"last_event",
        "checksum_field":"checksum",
        "range_checksum_query_json":
            {
                "row_filter":"WHERE board_serial BETWEEN '?' and '?' ORDER BY board_serial",
                "column_list":["board_serial, checksum"],
                "distinct_opt":false,
                "order_by_opt":"",
                "count_opt":100
            }
        })"
};


constexpr auto HOTFIXES_SQL_STATEMENT
{
    R"(CREATE TABLE dbsync_hotfixes(
    hotfix TEXT,
    checksum TEXT,
    PRIMARY KEY (hotfix)) WITHOUT ROWID;)"
};

constexpr auto HOTFIXES_SYNC_CONFIG_STATEMENT
{
    R"(
    {
        "decoder_type":"JSON_RANGE",
        "table":"dbsync_hotfixes",
        "component":"syscollector_hotfixes",
        "index":"hotfix",
        "checksum_field":"checksum",
        "no_data_query_json": {
                "row_filter":"WHERE hotfix BETWEEN '?' and '?' ORDER BY hotfix",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "count_range_query_json": {
                "row_filter":"WHERE hotfix BETWEEN '?' and '?' ORDER BY hotfix",
                "count_field_name":"count",
                "column_list":["count(*) AS count "],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "row_data_query_json": {
                "row_filter":"WHERE hotfix ='?'",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "range_checksum_query_json": {
                "row_filter":"WHERE hotfix BETWEEN '?' and '?' ORDER BY hotfix",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        }
    }
    )"
};

constexpr auto HOTFIXES_START_CONFIG_STATEMENT
{
    R"({"table":"dbsync_hotfixes",
        "first_query":
            {
                "column_list":["hotfix"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"hotfix DESC",
                "count_opt":1
            },
        "last_query":
            {
                "column_list":["hotfix"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"hotfix ASC",
                "count_opt":1
            },
        "component":"syscollector_hotfixes",
        "index":"hotfix",
        "last_event":"last_event",
        "checksum_field":"checksum",
        "range_checksum_query_json":
            {
                "row_filter":"WHERE hotfix BETWEEN '?' and '?' ORDER BY hotfix",
                "column_list":["hotfix, checksum"],
                "distinct_opt":false,
                "order_by_opt":"",
                "count_opt":100
            }
        })"
};

constexpr auto PACKAGES_SQL_STATEMENT
{
    R"(CREATE TABLE dbsync_packages(
    name TEXT,
    version TEXT,
    vendor TEXT,
    install_time TEXT,
    location TEXT,
    architecture TEXT,
    groups TEXT,
    description TEXT,
    size BIGINT,
    priority TEXT,
    multiarch TEXT,
    source TEXT,
    format TEXT,
    checksum TEXT,
    item_id TEXT,
    PRIMARY KEY (name,version,architecture,format,location)) WITHOUT ROWID;)"
};
static const std::vector<std::string> PACKAGES_ITEM_ID_FIELDS{"name", "version", "architecture", "format", "location"};

constexpr auto PACKAGES_SYNC_CONFIG_STATEMENT
{
    R"(
    {
        "decoder_type":"JSON_RANGE",
        "table":"dbsync_packages",
        "component":"syscollector_packages",
        "index":"item_id",
        "checksum_field":"checksum",
        "no_data_query_json": {
                "row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "count_range_query_json": {
                "row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id",
                "count_field_name":"count",
                "column_list":["count(*) AS count "],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "row_data_query_json": {
                "row_filter":"WHERE item_id ='?'",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "range_checksum_query_json": {
                "row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        }
    }
    )"
};

constexpr auto PACKAGES_START_CONFIG_STATEMENT
{
    R"({"table":"dbsync_packages",
        "first_query":
            {
                "column_list":["item_id"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"item_id DESC",
                "count_opt":1
            },
        "last_query":
            {
                "column_list":["item_id"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"item_id ASC",
                "count_opt":1
            },
        "component":"syscollector_packages",
        "index":"item_id",
        "last_event":"last_event",
        "checksum_field":"checksum",
        "range_checksum_query_json":
            {
                "row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id",
                "column_list":["item_id, checksum"],
                "distinct_opt":false,
                "order_by_opt":"",
                "count_opt":100
            }
        })"
};

constexpr auto PROCESSES_START_CONFIG_STATEMENT
{
    R"({"table":"dbsync_processes",
        "first_query":
            {
                "column_list":["pid"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"pid DESC",
                "count_opt":1
            },
        "last_query":
            {
                "column_list":["pid"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"pid ASC",
                "count_opt":1
            },
        "component":"syscollector_processes",
        "index":"pid",
        "last_event":"last_event",
        "checksum_field":"checksum",
        "range_checksum_query_json":
            {
                "row_filter":"WHERE pid BETWEEN '?' and '?' ORDER BY pid",
                "column_list":["pid, checksum"],
                "distinct_opt":false,
                "order_by_opt":"",
                "count_opt":1000
            }
        })"
};

constexpr auto PROCESSES_SYNC_CONFIG_STATEMENT
{
    R"(
    {
        "decoder_type":"JSON_RANGE",
        "table":"dbsync_processes",
        "component":"syscollector_processes",
        "index":"pid",
        "checksum_field":"checksum",
        "no_data_query_json": {
                "row_filter":"WHERE pid BETWEEN '?' and '?' ORDER BY pid",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "count_range_query_json": {
                "row_filter":"WHERE pid BETWEEN '?' and '?' ORDER BY pid",
                "count_field_name":"count",
                "column_list":["count(*) AS count "],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "row_data_query_json": {
                "row_filter":"WHERE pid ='?'",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "range_checksum_query_json": {
                "row_filter":"WHERE pid BETWEEN '?' and '?' ORDER BY pid",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        }
    }
    )"
};

constexpr auto PROCESSES_SQL_STATEMENT
{
    R"(CREATE TABLE dbsync_processes (
    pid TEXT,
    name TEXT,
    state TEXT,
    ppid BIGINT,
    utime BIGINT,
    stime BIGINT,
    cmd TEXT,
    argvs TEXT,
    euser TEXT,
    ruser TEXT,
    suser TEXT,
    egroup TEXT,
    rgroup TEXT,
    sgroup TEXT,
    fgroup TEXT,
    priority BIGINT,
    nice BIGINT,
    size BIGINT,
    vm_size BIGINT,
    resident BIGINT,
    share BIGINT,
    start_time BIGINT,
    pgrp BIGINT,
    session BIGINT,
    nlwp BIGINT,
    tgid BIGINT,
    tty BIGINT,
    processor BIGINT,
    checksum TEXT,
    PRIMARY KEY (pid)) WITHOUT ROWID;)"
};

constexpr auto PORTS_START_CONFIG_STATEMENT
{
    R"({"table":"dbsync_ports",
        "first_query":
            {
                "column_list":["item_id"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"item_id DESC",
                "count_opt":1
            },
        "last_query":
            {
                "column_list":["item_id"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"item_id ASC",
                "count_opt":1
            },
        "component":"syscollector_ports",
        "index":"item_id",
        "last_event":"last_event",
        "checksum_field":"checksum",
        "range_checksum_query_json":
            {
                "row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id",
                "column_list":["item_id, checksum"],
                "distinct_opt":false,
                "order_by_opt":"",
                "count_opt":1000
            }
        })"
};

constexpr auto PORTS_SYNC_CONFIG_STATEMENT
{
    R"(
    {
        "decoder_type":"JSON_RANGE",
        "table":"dbsync_ports",
        "component":"syscollector_ports",
        "index":"item_id",
        "checksum_field":"checksum",
        "no_data_query_json": {
                "row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "count_range_query_json": {
                "row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id",
                "count_field_name":"count",
                "column_list":["count(*) AS count "],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "row_data_query_json": {
                "row_filter":"WHERE item_id ='?'",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "range_checksum_query_json": {
                "row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        }
    }
    )"
};

constexpr auto PORTS_SQL_STATEMENT
{
    R"(CREATE TABLE dbsync_ports (
       protocol TEXT,
       local_ip TEXT,
       local_port BIGINT,
       remote_ip TEXT,
       remote_port BIGINT,
       tx_queue BIGINT,
       rx_queue BIGINT,
       inode BIGINT,
       state TEXT,
       pid BIGINT,
       process TEXT,
       checksum TEXT,
       item_id TEXT,
       PRIMARY KEY (inode, protocol, local_ip, local_port)) WITHOUT ROWID;)"
};
static const std::vector<std::string> PORTS_ITEM_ID_FIELDS{"inode", "protocol", "local_ip", "local_port"};

constexpr auto NETIFACE_START_CONFIG_STATEMENT
{
    R"({"table":"dbsync_network_iface",
        "first_query":
            {
                "column_list":["item_id"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"item_id DESC",
                "count_opt":1
            },
        "last_query":
            {
                "column_list":["item_id"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"item_id ASC",
                "count_opt":1
            },
        "component":"syscollector_network_iface",
        "index":"item_id",
        "last_event":"last_event",
        "checksum_field":"checksum",
        "range_checksum_query_json":
            {
                "row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id",
                "column_list":["item_id, checksum"],
                "distinct_opt":false,
                "order_by_opt":"",
                "count_opt":1000
            }
        })"
};

constexpr auto NETIFACE_SYNC_CONFIG_STATEMENT
{
    R"(
    {
        "decoder_type":"JSON_RANGE",
        "table":"dbsync_network_iface",
        "component":"syscollector_network_iface",
        "index":"item_id",
        "checksum_field":"checksum",
        "no_data_query_json": {
                "row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "count_range_query_json": {
                "row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id",
                "count_field_name":"count",
                "column_list":["count(*) AS count "],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "row_data_query_json": {
                "row_filter":"WHERE item_id ='?'",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "range_checksum_query_json": {
                "row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        }
    }
    )"
};

constexpr auto NETIFACE_SQL_STATEMENT
{
    R"(CREATE TABLE dbsync_network_iface (
       name TEXT,
       adapter TEXT,
       type TEXT,
       state TEXT,
       mtu INTEGER,
       mac TEXT,
       tx_packets INTEGER,
       rx_packets INTEGER,
       tx_bytes INTEGER,
       rx_bytes INTEGER,
       tx_errors INTEGER,
       rx_errors INTEGER,
       tx_dropped INTEGER,
       rx_dropped INTEGER,
       checksum TEXT,
       item_id TEXT,
       PRIMARY KEY (name,adapter,type)) WITHOUT ROWID;)"
};
static const std::vector<std::string> NETIFACE_ITEM_ID_FIELDS{"name", "adapter", "type"};

constexpr auto NETPROTO_START_CONFIG_STATEMENT
{
    R"({"table":"dbsync_network_protocol",
        "first_query":
            {
                "column_list":["item_id"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"item_id DESC",
                "count_opt":1
            },
        "last_query":
            {
                "column_list":["item_id"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"item_id ASC",
                "count_opt":1
            },
        "component":"syscollector_network_protocol",
        "index":"item_id",
        "last_event":"last_event",
        "checksum_field":"checksum",
        "range_checksum_query_json":
            {
                "row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id",
                "column_list":["item_id, checksum"],
                "distinct_opt":false,
                "order_by_opt":"",
                "count_opt":1000
            }
        })"
};

constexpr auto NETPROTO_SYNC_CONFIG_STATEMENT
{
    R"(
    {
        "decoder_type":"JSON_RANGE",
        "table":"dbsync_network_protocol",
        "component":"syscollector_network_protocol",
        "index":"item_id",
        "checksum_field":"checksum",
        "no_data_query_json": {
                "row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "count_range_query_json": {
                "row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id",
                "count_field_name":"count",
                "column_list":["count(*) AS count "],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "row_data_query_json": {
                "row_filter":"WHERE item_id ='?'",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "range_checksum_query_json": {
                "row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        }
    }
    )"
};

constexpr auto NETPROTO_SQL_STATEMENT
{
    R"(CREATE TABLE dbsync_network_protocol (
       iface TEXT,
       type TEXT,
       gateway TEXT,
       dhcp TEXT NOT NULL CHECK (dhcp IN ('enabled', 'disabled', 'unknown', 'BOOTP')) DEFAULT 'unknown',
       metric TEXT,
       checksum TEXT,
       item_id TEXT,
       PRIMARY KEY (iface,type)) WITHOUT ROWID;)"
};
static const std::vector<std::string> NETPROTO_ITEM_ID_FIELDS{"iface", "type"};

constexpr auto NETADDRESS_START_CONFIG_STATEMENT
{
    R"({"table":"dbsync_network_address",
        "first_query":
            {
                "column_list":["item_id"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"item_id DESC",
                "count_opt":1
            },
        "last_query":
            {
                "column_list":["item_id"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"item_id ASC",
                "count_opt":1
            },
        "component":"syscollector_network_address",
        "index":"item_id",
        "last_event":"last_event",
        "checksum_field":"checksum",
        "range_checksum_query_json":
            {
                "row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id",
                "column_list":["item_id, checksum"],
                "distinct_opt":false,
                "order_by_opt":"",
                "count_opt":1000
            }
        })"
};

constexpr auto NETADDRESS_SYNC_CONFIG_STATEMENT
{
    R"(
    {
        "decoder_type":"JSON_RANGE",
        "table":"dbsync_network_address",
        "component":"syscollector_network_address",
        "index":"item_id",
        "checksum_field":"checksum",
        "no_data_query_json": {
                "row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "count_range_query_json": {
                "row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id",
                "count_field_name":"count",
                "column_list":["count(*) AS count "],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "row_data_query_json": {
                "row_filter":"WHERE item_id ='?'",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "range_checksum_query_json": {
                "row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        }
    }
    )"
};

constexpr auto NETADDR_SQL_STATEMENT
{
    R"(CREATE TABLE dbsync_network_address (
       iface TEXT,
       proto INTEGER,
       address TEXT,
       netmask TEXT,
       broadcast TEXT,
       checksum TEXT,
       item_id TEXT,
       PRIMARY KEY (iface,proto,address)) WITHOUT ROWID;)"
};
static const std::vector<std::string> NETADDRESS_ITEM_ID_FIELDS{"iface", "proto", "address"};

constexpr auto USERS_START_CONFIG_STATEMENT
{
    R"({"table":"dbsync_users",
        "first_query":
            {
                "column_list":["item_id"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"item_id DESC",
                "count_opt":1
            },
        "last_query":
            {
                "column_list":["item_id"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"item_id ASC",
                "count_opt":1
            },
        "component":"syscollector_ports",
        "index":"item_id",
        "last_event":"last_event",
        "checksum_field":"checksum",
        "range_checksum_query_json":
            {
                "row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id",
                "column_list":["item_id, checksum"],
                "distinct_opt":false,
                "order_by_opt":"",
                "count_opt":1000
            }
        })"
};

constexpr auto USERS_SYNC_CONFIG_STATEMENT
{
    R"(
    {
        "decoder_type":"JSON_RANGE",
        "table":"dbsync_users",
        "component":"syscollector_ports",
        "index":"item_id",
        "checksum_field":"checksum",
        "no_data_query_json": {
                "row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "count_range_query_json": {
                "row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id",
                "count_field_name":"count",
                "column_list":["count(*) AS count "],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "row_data_query_json": {
                "row_filter":"WHERE item_id ='?'",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "range_checksum_query_json": {
                "row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        }
    }
    )"
};

constexpr auto USERS_SQL_STATEMENT
{
    R"(CREATE TABLE dbsync_users (
       protocol TEXT,
       inode BIGINT,
       PRIMARY KEY (inode)) WITHOUT ROWID;)"
};
static const std::vector<std::string> USERS_ITEM_ID_FIELDS{"inode"};


constexpr auto GROUPS_START_CONFIG_STATEMENT
{
    R"({"table":"dbsync_groups",
        "first_query":
            {
                "column_list":["group_id"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"group_id DESC",
                "count_opt":1
            },
        "last_query":
            {
                "column_list":["group_id"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"group_id ASC",
                "count_opt":1
            },
        "component":"syscollector_groups",
        "index":"group_id",
        "last_event":"last_event",
        "checksum_field":"checksum",
        "range_checksum_query_json":
            {
                "row_filter":"WHERE group_id BETWEEN '?' and '?' ORDER BY group_id",
                "column_list":["group_id, checksum"],
                "distinct_opt":false,
                "order_by_opt":"",
                "count_opt":1000
            }
        })"
};

constexpr auto GROUPS_SYNC_CONFIG_STATEMENT
{
    R"(
    {
        "decoder_type":"JSON_RANGE",
        "table":"dbsync_groups",
        "component":"syscollector_groups",
        "index":"group_id",
        "checksum_field":"checksum",
        "no_data_query_json": {
                "row_filter":"WHERE group_id BETWEEN '?' and '?' ORDER BY group_id",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "count_range_query_json": {
                "row_filter":"WHERE group_id BETWEEN '?' and '?' ORDER BY group_id",
                "count_field_name":"count",
                "column_list":["count(*) AS count "],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "row_data_query_json": {
                "row_filter":"WHERE group_id ='?'",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "range_checksum_query_json": {
                "row_filter":"WHERE group_id BETWEEN '?' and '?' ORDER BY group_id",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        }
    }
    )"
};

constexpr auto GROUPS_SQL_STATEMENT
{
    R"(CREATE TABLE dbsync_groups (
    group_id BIGINT,
    group_name TEXT,
    group_description TEXT,
    group_id_signed BIGINT,
    group_uuid TEXT,
    group_is_hidden INTEGER,
    group_users TEXT,
    checksum TEXT,
    PRIMARY KEY (group_id)) WITHOUT ROWID;)"
};

constexpr auto NET_IFACE_TABLE    { "dbsync_network_iface"    };
constexpr auto NET_PROTOCOL_TABLE { "dbsync_network_protocol" };
constexpr auto NET_ADDRESS_TABLE  { "dbsync_network_address"  };
constexpr auto PACKAGES_TABLE     { "dbsync_packages"         };
constexpr auto HOTFIXES_TABLE     { "dbsync_hotfixes"         };
constexpr auto PORTS_TABLE        { "dbsync_ports"            };
constexpr auto PROCESSES_TABLE    { "dbsync_processes"        };
constexpr auto OS_TABLE           { "dbsync_osinfo"           };
constexpr auto HW_TABLE           { "dbsync_hwinfo"           };
constexpr auto USERS_TABLE        { "dbsync_users"            };
constexpr auto GROUPS_TABLE       { "dbsync_groups"           };
