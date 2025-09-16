# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2


from contextlib import contextmanager
from enum import Enum
from wazuh.core.exception import WazuhInternalError


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
    """Wazuh CTI client."""

    def __init__(self) -> None:
        # TODO initialize communication with wazuh-modulesd
        pass

    def get_auth_token_status(self) -> CTIAuthTokenStatus:
        """Get the current authentication token status.

        Returns
        -------
        CTIAuthTokenStatus
            Current authentication token status.
        """

        # TODO Request to wazuh-modulesd
        return CTIAuthTokenStatus.PENDING

    async def close(self):
        # TODO close communication with wazuh-modulesd
        pass

@contextmanager
def get_cti_client():
    """Create and return the CTI client.

    Returns
    -------
    AsyncIterator[CTI]
        CTI client iterator.
    """
    client = CTI()

    try:
        yield client
    # TODO add exceptions based on CTI token retrieval mechanism
    except Exception:
        raise WazuhInternalError(1000)
    finally:
        client.close()
