#!/usr/bin/env python
#
# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

####### Constants #######

TIME_FORMAT= '%Y-%m-%dT%H:%M:%S.%fZ'

### Table

ID_t= 'id'
VERSION_t= 'version'
NAME_t= 'name'
DESCRIPTION_t= 'description'
CREATED_t= 'created_time'
MODIFIED_t= 'modified_time'
MITRE_VERSION_t= 'mitre_version'
REVOKED_BY_t= 'revoked_by'
DEPRECATED_t= 'deprecated'
MITRE_DETECTION_t= 'mitre_detection'
NETWORK_REQ_t= 'network_requirements'
REMOTE_SUPPORT_t= 'remote_support'
SUBTECHNIQUE_OF_t= 'subtechnique_of'
SOURCE_t= 'source'
DEFENSE_t= 'defense'
PERMISSION_t= 'permission'
IMPACT_t= 'impact'
REQUIREMENT_t= 'requirement'

### Relationships
DATASOURCE_r= 'DataSource'
DEFENSEBYPASSES_r='DefenseByPasses'
EFFECTIVEPERMISSON_r= 'EffectivePermission'
IMPACT_r= 'Impact'
PERMISSION_r= 'Permission'
SYSTEMREQ_r= 'SystemRequirement'
TECHNIQUES_r= 'techniques'

TECHNIQUE_ID_fk= 'techniques.id'

### Json index

# Global
TYPE_j= 'type'
OBJECT_j= 'objects'
# Groups
INTRUSION_SET_j= 'intrusion-set'
# Mitigations
COURSE_OF_ACTION_j= 'course-of-action'
# Software
MALWARE_j= 'malware'
TOOL_j= 'tool'
# Techniques
ATTACK_PATTERN_j= 'attack-pattern'

ID_j= 'id'
VERSION_j= 'spec_version'
IDENTITY_j= 'identity'
MARKING_DEFINITION_j= 'marking-definition'
DEFINITION_j= 'definition'
STATEMENT_j= 'statement'
NAME_j= 'name'
DESCRIPTION_j= 'description'
CREATED_j= 'created'
MODIFIED_j= 'modified'
MITRE_VERSION_j= 'x_mitre_version'
SOURCE_REF_j='source_ref'
RELATIONSHIP_j= 'relationship'
RELATIONSHIP_TYPE_j= 'relationship_type'
REVOKED_BY_j= "revoked-by"
TARGET_REF_j= 'target_ref'
DEPRECATED_j='x_mitre_deprecated'
MITRE_DETECTION_j= 'x_mitre_detection'
MITRE_NETWOR_REQ_j= 'x_mitre_network_requirements'
MITRE_REMOTE_SUPP_j= 'x_mitre_remote_support'
SUBTECHNIQUEOF_j= 'subtechnique_of'
DATASOURCE_j= 'x_mitre_data_sources'
DEFENSE_BYPASSED_j= 'x_mitre_defense_bypassed'
EFFECTIVE_PERMISSION_j= 'x_mitre_effective_permissions'
IMPACT_TYPE_j= 'x_mitre_impact_type'
PERMISSIONS_REQ_j= 'x_mitre_permissions_required'
SYSTEM_REQ_j= 'x_mitre_system_requirements'
SUBTECHNIQUE_OF_j= 'subtechnique-of'
