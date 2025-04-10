# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import asyncio
import contextlib
import json
import logging
import os
import time
from concurrent.futures import process
from functools import partial
from typing import Callable, Dict
import wazuh.core.cluster.cluster
import wazuh.core.cluster.utils
import wazuh.core.manager
import wazuh.core.results as wresults
from sqlalchemy.exc import OperationalError
from wazuh.core import common, exception
from wazuh.core.config.client import CentralizedConfig
from wazuh.core.exception import WazuhException
from wazuh.core.rbac import RBACManager

pools = common.mp_pools.get()

authentication_funcs = {'check_token', 'check_user_master', 'get_permissions', 'get_security_conf'}
events_funcs = {'send_event_to_analysisd'}


class TaskDispatcher:
    """Represents a distributed API request."""

    def __init__(
        self,
        f: Callable,
        logger: logging.getLogger,
        f_kwargs: Dict = None,
        debug: bool = False,
        current_user: str = '',
        wait_for_complete: bool = False,
        is_async: bool = False,
        broadcasting: bool = False,
        basic_services: tuple = None,
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
        wait_for_complete : bool, optional
            True to disable timeout, false otherwise. Default `False`
        from_cluster : bool, optional
            Default `False`, specify if the request goes from cluster or not
        is_async : bool, optional
            Default `False`, specify if the request is asynchronous or not
        broadcasting : bool, optional
            Default `False`, True if the request need to be executed in all managers
        basic_services : tuple, optional
            Default `None`, services that must be started for correct behaviour
        local_client_arg: str, optional
            Default `None`, LocalClient additional arguments
        rbac_permissions : dict, optional
            Default `None`, RBAC user's permissions
        current_user : str
            User who started the request
        api_timeout : int
            Timeout set in source API for the request
        remove_denied_nodes : bool
            Whether to remove denied (RBAC) nodes from response's failed items or not.
        rbac_manager : RBACManager
            RBAC manager.
        """
        self.logger = logger
        self.f = f
        self.f_kwargs = f_kwargs if f_kwargs is not None else {}
        self.server_config = CentralizedConfig.get_server_config() if node is None else node.server_config
        self.debug = debug
        self.node_info = wazuh.core.cluster.cluster.get_node() if node is None else node.get_node()
        self.wait_for_complete = wait_for_complete
        self.is_async = is_async
        self.broadcasting = broadcasting
        self.rbac_permissions = rbac_permissions if rbac_permissions is not None else {'rbac_mode': 'black'}
        self.current_user = current_user
        self.origin_module = 'API'
        if not basic_services:
            self.basic_services = ('wazuh-server',)
        else:
            self.basic_services = basic_services

        self.local_clients = []
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
                    json.loads(response, object_hook=c_common.as_wazuh_object)
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
            e.dapi_errors = await self.get_error_info(e)
            if self.debug:
                raise
            self.logger.error(f'{e.message}')
            return e
        except exception.WazuhInternalError as e:
            e.dapi_errors = await self.get_error_info(e)
            if self.debug:
                raise
            self.logger.error(f'{e.message}', exc_info=not isinstance(e, exception.WazuhClusterError))
            return e
        except exception.WazuhError as e:
            e.dapi_errors = await self.get_error_info(e)
            return e
        except Exception as e:
            if self.debug:
                raise

            self.logger.error(f'Unhandled exception: {str(e)}', exc_info=True)
            return exception.WazuhInternalError(1000, dapi_errors=await self.get_error_info(e))

    def check_wazuh_status(self):
        """There are some services that are required for wazuh to correctly process API requests. If any of those services
        is not running, the API must raise an exception indicating that:
            * It's not ready yet to process requests if services are restarting
            * There's an error in any of those services that must be addressed before using the API if any service is
              in failed status.
            * Wazuh must be started before using the API is the services are stopped.

        The basic service wazuh needs to be running is: wazuh-clusterd.
        """
        if self.f == wazuh.core.manager.status:
            return

        status = wazuh.core.manager.status()

        not_ready_daemons = {
            k: status[k] for k in self.basic_services if status[k] in ('failed', 'restarting', 'stopped')
        }

        if not_ready_daemons:
            extra_info = {
                'node_name': self.node_info.get('node', 'UNKNOWN NODE'),
                'not_ready_daemons': ', '.join([f'{key}->{value}' for key, value in not_ready_daemons.items()]),
            }
            raise exception.WazuhInternalError(1017, extra_message=extra_info)

    @staticmethod
    def run_local(f, f_kwargs, rbac_permissions, broadcasting, nodes, current_user, origin_module, rbac_manager):
        """Run framework SDK function locally in another process."""
        common.rbac.set(rbac_permissions)
        common.broadcast.set(broadcasting)
        common.cluster_nodes.set(nodes)
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
            self.check_wazuh_status()

            timeout = self.api_request_timeout if not self.wait_for_complete else None

            try:
                if self.is_async:
                    task = self.run_local(
                        self.f,
                        self.f_kwargs,
                        self.rbac_permissions,
                        self.broadcasting,
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
                    elif self.f.__name__ in events_funcs:
                        pool = pools.get('events_pool')
                    else:
                        pool = pools.get('process_pool')

                    task = loop.run_in_executor(
                        pool,
                        partial(
                            self.run_local,
                            self.f,
                            self.f_kwargs,
                            self.rbac_permissions,
                            self.broadcasting,
                            self.nodes,
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
                except OperationalError as exc:
                    raise exception.WazuhInternalError(2008, extra_message=str(exc.orig))
                except process.BrokenProcessPool:
                    raise exception.WazuhInternalError(901)
            except json.decoder.JSONDecodeError:
                raise exception.WazuhInternalError(3036)
            except process.BrokenProcessPool:
                raise exception.WazuhInternalError(900)

            self.debug_log(f'Time calculating request result: {time.time() - before:.3f}s')
            return data
        except exception.WazuhInternalError as e:
            e.dapi_errors = await self.get_error_info(e)
            # Avoid exception info if it is an asyncio timeout error, JSONDecodeError, /proc availability error or
            # WazuhClusterError
            self.logger.error(
                f'{e.message}',
                exc_info=e.code not in {3021, 3036, 1913, 1017} and not isinstance(e, exception.WazuhClusterError),
            )
            if self.debug:
                raise
            return json.dumps(e, cls=c_common.WazuhJSONEncoder)
        except (exception.WazuhError, exception.WazuhResourceNotFound) as e:
            e.dapi_errors = await self.get_error_info(e)
            if self.debug:
                raise
            return json.dumps(e, cls=c_common.WazuhJSONEncoder)
        except Exception as e:
            self.logger.error(f'Error executing API request locally: {str(e)}', exc_info=True)
            if self.debug:
                raise
            return json.dumps(
                exception.WazuhInternalError(1000, dapi_errors=await self.get_error_info(e)),
                cls=c_common.WazuhJSONEncoder,
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
            'local_client_arg': self.local_client_arg,
            'basic_services': self.basic_services,
            'rbac_permissions': self.rbac_permissions,
            'current_user': self.current_user,
            'broadcasting': self.broadcasting,
            'api_timeout': self.api_request_timeout,
        }

    async def get_error_info(self, e: Exception) -> Dict:
        """Build a response given an Exception.

        Parameters
        ----------
        e : Exception
            Exception to parse.

        Returns
        -------
        dict
            Dict where keys are nodes and values are error information.
        """
        try:
            common.rbac.set(self.rbac_permissions)
            node_wrapper = await get_node_wrapper()
            node = node_wrapper.affected_items[0]['node']
        except exception.WazuhException as rbac_exception:
            if rbac_exception.code == 4000:
                node = 'unknown-node'
            else:
                raise rbac_exception
        except IndexError:
            raise list(node_wrapper.failed_items.keys())[0]

        error_message = e.message if isinstance(e, exception.WazuhException) else exception.GENERIC_ERROR_MSG
        result = {node: {'error': error_message}}

        # Give log path only in case of WazuhInternalError
        if isinstance(e, exception.WazuhInternalError):
            log_filename = None
            for h in self.logger.handlers or self.logger.parent.handlers:
                if hasattr(h, 'baseFilename'):
                    log_filename = os.path.join('WAZUH_LOG', os.path.relpath(h.baseFilename, start=common.WAZUH_LOG))
            result[node]['logfile'] = log_filename

        return result
