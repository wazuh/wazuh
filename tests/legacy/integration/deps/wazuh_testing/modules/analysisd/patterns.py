from . import TESTRULE_PREFIX

# Callback patterns to find events,
SID_NOT_FOUND = r".*Signature ID '(\d*)' was not found and will be ignored in the 'if_sid'.* of rule '(\d*)'"
EMPTY_IF_SID_RULE_IGNORED = fr"{TESTRULE_PREFIX}Empty 'if_sid' value. Rule '(\d*)' will be ignored.*"
INVALID_IF_SID_RULE_IGNORED = fr"{TESTRULE_PREFIX}Invalid 'if_sid' value: '(.*)'. Rule '(\d*)' will be ignored.*"
INVALID_EMPTY_IF_SID_RULE_IGNORED = fr"{TESTRULE_PREFIX}Invalid 'if_sid' value: ''. Rule '(\d*)' will be ignored.*"
