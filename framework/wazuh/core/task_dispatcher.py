# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import asyncio
import json
import logging
import os
import time
from concurrent.futures import process
from functools import partial
from typing import Callable, Dict
import wazuh.core.results as wresults
from wazuh.core import common, exception
from wazuh.core.config.client import CentralizedConfig
from wazuh.core.rbac import RBACManager

pools = common.mp_pools.get()

authentication_funcs = {'check_token', 'check_user_master', 'get_permissions', 'get_security_conf'}

class TaskDispatcher:
    """Represents a task dispatch request."""

    def __init__(
        self,
        f: Callable,
        logger: logging.getLogger,
        f_kwargs: Dict = None,
        debug: bool = False,
        current_user: str = '',
        wait_for_complete: bool = False,
        is_async: bool = False,
        rbac_permissions: Dict = None,
        api_timeout: int = None,
        rbac_manager: RBACManager = None,
    ):
        """Class constructor.

        Parameters
        ----------
        f : callable
            Function to be executed.
        logger : logging.getLogger
            Logging logger to use.
        f_kwargs : dict, optional
            Arguments to be passed to function `f`. Default `None`
        debug : bool, optional
            Enable debug messages and raise exceptions. Default `False`
        current_user : str
            User who started the request
        wait_for_complete : bool, optional
            True to disable timeout, false otherwise. Default `False`
        is_async : bool, optional
            Default `False`, specify if the request is asynchronous or not
        rbac_permissions : dict, optional
            Default `None`, RBAC user's permissions
        api_timeout : int
            Timeout set in source API for the request
        rbac_manager : RBACManager
            RBAC manager.
        """
        self.logger = logger
        self.f = f
        self.f_kwargs = f_kwargs if f_kwargs is not None else {}
        self.debug = debug
        self.wait_for_complete = wait_for_complete
        self.is_async = is_async
        self.rbac_permissions = rbac_permissions if rbac_permissions is not None else {'rbac_mode': 'black'}
        self.current_user = current_user
        self.origin_module = 'API'
        api_request_timeout = CentralizedConfig.get_management_api_config().intervals.request_timeout
        self.api_request_timeout = max(api_timeout, api_request_timeout) if api_timeout else api_request_timeout
        self.rbac_manager = rbac_manager

    def debug_log(self, message):
        """Use debug or debug2 depending on the log type.

        Parameters
        ----------
        message : str
            Full log message.
        """
        if self.logger.name == 'wazuh-api':
            self.logger.debug2(message)
        else:
            self.logger.debug(message)

    async def execute_function(self) -> Dict | exception.WazuhException:  # noqa: C901
        """Distribute an API call.

        Returns
        -------
        dict or WazuhException
            Dictionary with API response or WazuhException in case of error.
        """
        try:
            if 'password' in self.f_kwargs:
                self.debug_log(f'Receiving parameters { {**self.f_kwargs, "password": "****"} }')
            elif 'token_nbf_time' in self.f_kwargs:
                self.logger.debug(f'Decoded token {self.f_kwargs}')
            else:
                self.debug_log(f'Receiving parameters {self.f_kwargs}')

            response = await self.execute_local_request()

            try:
                response = (
                    json.loads(response)
                    if isinstance(response, str)
                    else response
                )
            except json.decoder.JSONDecodeError:
                response = {'message': response}

            return (
                response
                if isinstance(response, (wresults.AbstractWazuhResult, exception.WazuhException))
                else wresults.WazuhResult(response)
            )

        except json.decoder.JSONDecodeError:
            e = exception.WazuhInternalError(3036)
            if self.debug:
                raise
            self.logger.error(f'{e.message}')
            return e
        except exception.WazuhInternalError as e:
            if self.debug:
                raise
            self.logger.error(f'{e.message}', exc_info=not isinstance(e, exception.WazuhClusterError))
            return e
        except exception.WazuhError as e:
            return e
        except Exception as e:
            if self.debug:
                raise

            self.logger.error(f'Unhandled exception: {str(e)}', exc_info=True)
            return exception.WazuhInternalError(1000)


    @staticmethod
    def run_local(f, f_kwargs, rbac_permissions, current_user, origin_module, rbac_manager):
        """Run framework SDK function locally in another process."""
        common.rbac.set(rbac_permissions)
        common.current_user.set(current_user)
        common.origin_module.set(origin_module)
        common.rbac_manager.set(rbac_manager)
        data = f(**f_kwargs)
        common.reset_context_cache()
        return data

    async def execute_local_request(self) -> str:  # noqa: C901
        """Execute an API request locally.

        Returns
        -------
        str
            JSON response.
        """
        try:
            if self.f_kwargs.get('agent_list') == '*':
                del self.f_kwargs['agent_list']

            before = time.time()

            timeout = self.api_request_timeout if not self.wait_for_complete else None

            try:
                if self.is_async:
                    task = self.run_local(
                        self.f,
                        self.f_kwargs,
                        self.rbac_permissions,
                        self.current_user,
                        self.origin_module,
                        self.rbac_manager,
                    )

                else:
                    loop = asyncio.get_event_loop()
                    if 'thread_pool' in pools:
                        pool = pools.get('thread_pool')
                    elif self.f.__name__ in authentication_funcs:
                        pool = pools.get('authentication_pool')
                    else:
                        pool = pools.get('process_pool')

                    task = loop.run_in_executor(
                        pool,
                        partial(
                            self.run_local,
                            self.f,
                            self.f_kwargs,
                            self.rbac_permissions,
                            self.current_user,
                            self.origin_module,
                            self.rbac_manager,
                        ),
                    )
                try:
                    self.debug_log('Starting to execute request locally')
                    data = await asyncio.wait_for(task, timeout=timeout)
                    self.debug_log('Finished executing request locally')
                except asyncio.TimeoutError:
                    raise exception.WazuhInternalError(3021)
                except process.BrokenProcessPool:
                    raise exception.WazuhInternalError(901)
            except json.decoder.JSONDecodeError:
                raise exception.WazuhInternalError(3036)
            except process.BrokenProcessPool:
                raise exception.WazuhInternalError(900)

            self.debug_log(f'Time calculating request result: {time.time() - before:.3f}s')
            return data
        except Exception as e:
            self.logger.error(f'Error executing API request locally: {str(e)}', exc_info=True)
            if self.debug:
                raise
            return json.dumps(
                exception.WazuhInternalError(1000)
            )

    def to_dict(self):
        """Convert object into a dictionary.

        Returns
        -------
        dict
            Dictionary containing the key values.
        """
        return {
            'f': self.f,
            'f_kwargs': self.f_kwargs,
            'wait_for_complete': self.wait_for_complete,
            'is_async': self.is_async,
            'rbac_permissions': self.rbac_permissions,
            'current_user': self.current_user,
            'api_timeout': self.api_request_timeout,
        }
