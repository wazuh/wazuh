#!/usr/bin/env python
#
# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

####### Constants #######

### Table

# Global
OBJECT_j= 'objects'
# Groups
GROUPS = 'Groups'
# Mitigations
MITIGATION = 'Mitigations'
# Software
SOFTWARE = 'Software'

ID_t= 'id'
VERSION_t= 'version'
NAME_t= 'name'
DESCRIPTION_t= 'description'
CREATED_t= 'created_time'
MODIFIED_t= 'modified_time'
MITRE_VERSION_t= 'mitre_version'
REVOKED_BY_t= "revoked_by"
DEPRECATED_t='deprecated'

### Json index

# Global
TYPE_j= 'type'
# Groups
INSTRUSION_SET_j= 'intrusion-set'
# Mitigations
COURSE_OF_ACTION_j= 'course-of-action'
# Software
MALWARE_j= 'malware'
TOOL_j= 'tool'

ID_j= 'id'
NAME_j= 'name'
DESCRIPTION_j= 'description'
CREATED_j= 'created'
MODIFIED_j= 'modified'
MITRE_VERSION_j= 'x_mitre_version'
REVOKED_j= 'revoked'
SORUCE_REF_j='source_ref'
RELATIONSHIP_TYPE_j= 'relationship_type'
REVOKED_BY_j= "revoked-by"
TARGET_REF_j= 'target_ref'
DEPRECATED_j='x_mitre_deprecated'