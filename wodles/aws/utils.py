# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2


def check_role_session_duration(duration: int or None) -> bool:
    """Checks if the role session duration specified is a valid parameter.

    Parameters
    ----------
    duration: int or None
        The desired session duration in seconds.
    """
    # Session duration must be between 15m and 12h
    return duration is None or (900 <= duration <= 43200)
