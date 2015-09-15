cmd_Release/bson.node := ln -f "Release/obj.target/bson.node" "Release/bson.node" 2>/dev/null || (rm -rf "Release/bson.node" && cp -af "Release/obj.target/bson.node" "Release/bson.node")
