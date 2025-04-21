# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import ast
import asyncio
import datetime
import json
import logging
import time
from concurrent.futures import process
from functools import partial
from importlib import import_module
from typing import Callable, Dict

import wazuh.core.results as wresults
from wazuh import Wazuh
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
                response = json.loads(response, object_hook=as_wazuh_object) if isinstance(response, str) else response
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
        except exception.WazuhInternalError as e:
            self.logger.error(
                f'{e.message}',
                exc_info=e.code not in {3021, 3036, 1913, 1017},
            )
            if self.debug:
                raise
            return json.dumps(e, cls=WazuhJSONEncoder)
        except (exception.WazuhError, exception.WazuhResourceNotFound) as e:
            if self.debug:
                raise
            return json.dumps(e, cls=WazuhJSONEncoder)
        except Exception as e:
            self.logger.error(f'Error executing API request locally: {str(e)}', exc_info=True)
            if self.debug:
                raise
            return json.dumps(
                exception.WazuhInternalError(1000),
                cls=WazuhJSONEncoder,
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


class WazuhJSONEncoder(json.JSONEncoder):
    """Define special JSON encoder for Wazuh."""

    def default(self, obj):
        """Serialize special Wazuh-related objects to JSON.

        Override the default serialization behavior to handle additional Python types
        used in Wazuh, including callables, custom exceptions, results, datetime objects,
        and generic exceptions.

        Parameters
        ----------
        obj : Any
            The object to be serialized.

        Returns
        -------
        Any
            A JSON-serializable object representing the original value.

        Raises
        ------
        TypeError
            If the object cannot be serialized.
        """
        if callable(obj):
            return self._encode_callable(obj)
        if isinstance(obj, exception.WazuhException):
            return self._encode_wazuh_exception(obj)
        if isinstance(obj, wresults.AbstractWazuhResult):
            return self._encode_wazuh_result(obj)
        if isinstance(obj, (datetime.datetime, datetime.date)):
            return self._encode_datetime(obj)
        if isinstance(obj, Exception):
            return self._encode_unhandled_exception(obj)

        return super().default(obj)

    def _encode_callable(self, obj):
        result = {'__callable__': {}}
        attributes = result['__callable__']
        if hasattr(obj, '__name__'):
            attributes['__name__'] = obj.__name__
        if hasattr(obj, '__module__'):
            attributes['__module__'] = obj.__module__
        if hasattr(obj, '__qualname__'):
            attributes['__qualname__'] = obj.__qualname__
        if hasattr(obj, '__self__') and isinstance(obj.__self__, Wazuh):
            attributes['__wazuh__'] = obj.__self__.to_dict()
        attributes['__type__'] = type(obj).__name__
        return result

    def _encode_wazuh_exception(self, obj):
        return {'__wazuh_exception__': {'__class__': obj.__class__.__name__, '__object__': obj.to_dict()}}

    def _encode_wazuh_result(self, obj):
        return {'__wazuh_result__': {'__class__': obj.__class__.__name__, '__object__': obj.encode_json()}}

    def _encode_datetime(self, obj):
        return {'__wazuh_datetime__': obj.isoformat()}

    def _encode_unhandled_exception(self, obj):
        return {'__unhandled_exc__': {'__class__': obj.__class__.__name__, '__args__': obj.args}}


def as_wazuh_object(dct: Dict):
    """Deserialize a dictionary into a Wazuh-related Python object.

    Act as a custom `object_hook` for `json.loads`, reconstructing Wazuh-specific
    objects from their serialized form, such as:
    - Callables (functions and methods)
    - WazuhException instances
    - AbstractWazuhResult objects
    - datetime objects (from ISO format)
    - Generic exceptions

    Parameters
    ----------
    dct : dict
        The dictionary potentially representing a serialized Wazuh object.

    Returns
    -------
    Any
        The deserialized Python object, or the original dictionary if no special decoding is needed.

    Raises
    ------
    WazuhInternalError
        If the dictionary contains an unrecognized or invalid format for decoding.
    """
    try:
        if '__callable__' in dct:
            encoded_callable = dct['__callable__']
            funcname = encoded_callable['__name__']
            if '__wazuh__' in encoded_callable:
                # Encoded Wazuh instance method.
                wazuh = Wazuh()
                return getattr(wazuh, funcname)
            else:
                # Encoded function or static method.
                qualname = encoded_callable['__qualname__'].split('.')
                classname = qualname[0] if len(qualname) > 1 else None
                module_path = encoded_callable['__module__']
                module = import_module(module_path)
                if classname is None:
                    return getattr(module, funcname)
                else:
                    return getattr(getattr(module, classname), funcname)
        elif '__wazuh_exception__' in dct:
            wazuh_exception = dct['__wazuh_exception__']
            return getattr(exception, wazuh_exception['__class__']).from_dict(wazuh_exception['__object__'])
        elif '__wazuh_result__' in dct:
            wazuh_result = dct['__wazuh_result__']
            return getattr(wresults, wazuh_result['__class__']).decode_json(wazuh_result['__object__'])
        elif '__wazuh_datetime__' in dct:
            return datetime.datetime.fromisoformat(dct['__wazuh_datetime__'])
        elif '__unhandled_exc__' in dct:
            exc_data = dct['__unhandled_exc__']
            exc_dict = {exc_data['__class__']: exc_data['__args__']}
            return ast.literal_eval(json.dumps(exc_dict))
        return dct

    except (KeyError, AttributeError):
        raise exception.WazuhInternalError(
            1000, extra_message=f'Wazuh object cannot be decoded from JSON {dct}', cmd_error=True
        )
