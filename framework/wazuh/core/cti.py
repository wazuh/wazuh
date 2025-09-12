# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2


from enum import Enum


class CTIAuthTokenStatus(Enum):
    """Enumeration of possible CTI authentication token states.

    Each status contains a short and long description for better context.

    Attributes
    ----------
    PENDING : CTIAuthTokenStatus
        Registration process was not started and never tried.
    POLLING : CTIAuthTokenStatus
        Registration process is being carried out.
    DENIED : CTIAuthTokenStatus
        Registration process denied due to expired `device_code`.
    AVAILABLE : CTIAuthTokenStatus
        Registration process was finished successfully.
    """

    PENDING = ("pending", "Registration process was not started and never tried.")
    POLLING = ("polling", "Registration process is being carried out.")
    DENIED = ("denied", "Registration process denied due to expired `device_code`.")
    AVAILABLE = ("available", "Registration process was finished successfuly.")

    def __init__(self, short_desc: str, long_desc: str):
        """Initialize enum value with short and long descriptions.

        Parameters
        ----------
        short_desc : str
            Short description of the status (identifier).
        long_desc : str
            Detailed explanation of the status meaning.
        """
        self.short_desc = short_desc
        self.long_desc = long_desc


class CTI:
    """Client that manages the CTI authentication token process."""

    def __init__(self):
        """Initialize CTI."""
        self.status = CTIAuthTokenStatus.PENDING

    def get_auth_token_status(self) -> CTIAuthTokenStatus:
        """Get the current authentication token status.

        Returns
        -------
        CTIAuthTokenStatus
            Current authentication token status.
        """
        return self.status

cti = CTI()
