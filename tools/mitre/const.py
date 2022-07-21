#!/usr/bin/env python
#
# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

####### Constants #######

TIME_FORMAT= '%Y-%m-%dT%H:%M:%S.%fZ'

####### Columns #######

### Common
ID_t= 'id'
NAME_t= 'name'
DESCRIPTION_t= 'description'
CREATED_t= 'created_time'
MODIFIED_t= 'modified_time'
MITRE_VERSION_t= 'mitre_version'
REVOKED_BY_t= 'revoked_by'
DEPRECATED_t= 'deprecated'
TYPE_t= 'type'

### Metadata
KEY_t= 'key'
VALUE_t= 'value'
DB_VERSION_t = 'db_version'
DB_VERSION_N_t = '1'
MITRE_VERSION_t = 'mitre_version'

### Technique
MITRE_DETECTION_t= 'mitre_detection'
NETWORK_REQ_t= 'network_requirements'
REMOTE_SUPPORT_t= 'remote_support'
SUBTECHNIQUE_OF_t= 'subtechnique_of'
SOURCE_t= 'source'
DEFENSE_t= 'defense'
PERMISSION_t= 'permission'
IMPACT_t= 'impact'
REQUIREMENT_t= 'requirement'

### Tactic
SHORT_NAME_t= 'short_name'

### Common tables
ALIAS_t= 'alias'
CONTRIBUTOR_t= 'contributor'
PLATFORM_t= 'platform'
SOURCE_t= 'source'
EXTERNAL_ID_t= 'external_id'
URL_t= 'url'

### Relationship
SOURCE_ID_t= 'source_id'
TARGET_ID_t= 'target_id'
TACTIC_ID_t= 'tactic_id'
TECH_ID_t= 'tech_id'

### Use
SOURCE_TYPE_t= 'source_type'
TARGET_TYPE_t= 'target_type'

####### Relationships #######

### Names
DATASOURCE_r= 'DataSource'
DEFENSEBYPASSES_r= 'DefenseByPasses'
EFFECTIVEPERMISSON_r= 'EffectivePermission'
IMPACT_r= 'Impact'
PERMISSION_r= 'Permission'
SYSTEMREQ_r= 'SystemRequirement'
TECHNIQUES_r= 'technique'
MITIGATE_r= 'Mitigate'
PHASE_r= 'Phase'

### ForeignKey
TECHNIQUE_ID_fk= 'technique.id'
MITIGATION_ID_fk= 'mitigation.id'
TACTIC_ID_fk= 'tactic.id'

####### JSON indexes #######

### Global
TYPE_j= 'type'
OBJECT_j= 'objects'

### Types
ATTACK_PATTERN_j= 'attack-pattern'
TACTIC_j= 'x-mitre-tactic'
COURSE_OF_ACTION_j= 'course-of-action'
INTRUSION_SET_j= 'intrusion-set'
MALWARE_j= 'malware'
TOOL_j= 'tool'

### Common
ID_j= 'id'
NAME_j= 'name'
DESCRIPTION_j= 'description'
CREATED_j= 'created'
MODIFIED_j= 'modified'
MITRE_VERSION_j= 'x_mitre_version'
DEPRECATED_j= 'x_mitre_deprecated'

### Metadata
VERSION_j= 'spec_version'

### Technique
MITRE_DETECTION_j= 'x_mitre_detection'
MITRE_NETWOR_REQ_j= 'x_mitre_network_requirements'
MITRE_REMOTE_SUPP_j= 'x_mitre_remote_support'
DATASOURCE_j= 'x_mitre_data_sources'
DEFENSE_BYPASSED_j= 'x_mitre_defense_bypassed'
EFFECTIVE_PERMISSION_j= 'x_mitre_effective_permissions'
IMPACT_TYPE_j= 'x_mitre_impact_type'
PERMISSIONS_REQ_j= 'x_mitre_permissions_required'
SYSTEM_REQ_j= 'x_mitre_system_requirements'

### Tactic
SHORT_NAME_j= 'x_mitre_shortname'

### Common tables
ALIAS_j= 'x_mitre_aliases'
ALIASES_j= 'aliases'
CONTRIBUTOR_j= 'x_mitre_contributors'
PLATFORM_j= 'x_mitre_platforms'
EXTERNAL_REFERENCES_j= 'external_references'
SOURCE_NAME_j= 'source_name'
EXTERNAL_ID_j= 'external_id'
URL_j= 'url'

### Relationship
PHASES_j= 'kill_chain_phases'
PHASE_NAME_j= 'phase_name'
RELATIONSHIP_j= 'relationship'
SOURCE_REF_j= 'source_ref'
TARGET_REF_j= 'target_ref'
RELATIONSHIP_TYPE_j= 'relationship_type'
MITIGATES_j= 'mitigates'
USES_j= 'uses'
REVOKED_BY_j= 'revoked-by'
SUBTECHNIQUE_OF_j= 'subtechnique-of'
