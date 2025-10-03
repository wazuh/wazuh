# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os, json
from typing import List, Optional
from wazuh.core.engine.base import BaseModule
from wazuh.core.engine.models.policies import PolicyType
from wazuh.core.engine.models.resources import ResourceType, ResourceFormat, Status
from wazuh.core.common import USER_TESTING_KVDB_PATH, USER_PRODUCTION_KVDB_PATH
from wazuh.core.assets import save_asset_file

META_SUFFIX = '.meta.json'


def _base_dir(policy_type: PolicyType) -> str:
    """Return the KVDB base directory for the given policy.

    Parameters
    ----------
    policy_type : PolicyType
        TESTING or PRODUCTION.

    Returns
    -------
    str
        Absolute path to the KVDB base directory for the policy.
    """
    return USER_TESTING_KVDB_PATH if policy_type == PolicyType.TESTING else USER_PRODUCTION_KVDB_PATH


def _meta_path(policy_type: PolicyType, name: str) -> str:
    """Build the absolute path to the sidecar metadata file for a KVDB resource.

    Parameters
    ----------
    policy_type : PolicyType
        TESTING or PRODUCTION.
    name : str
        KVDB resource identifier.

    Returns
    -------
    str
        Full path to '<base>/<name>.meta.json'.
    """
    return os.path.join(_base_dir(policy_type), f"{name}{META_SUFFIX}")


class ContentModule(BaseModule):
    """Module to interact with Engine content resources."""

    async def create_resource(
        self,
        type: ResourceType,
        format: ResourceFormat,
        content: str,
        policy_type: PolicyType,
        name: Optional[str] = None,
        integration_id: Optional[str] = None,
        display_name: Optional[str] = None,
        **kwargs
    ) -> dict:
        """Create a content resource and persist sidecar metadata on disk.

        Parameters
        ----------
        type : ResourceType
            Resource type to create (e.g., KVDB).
        format : ResourceFormat
            Content format (e.g., JSON).
        content : str
            Resource payload serialized as string.
        policy_type : PolicyType
            Policy scope where the resource belongs (TESTING/PRODUCTION).
        name : str, optional
            Resource identifier.
        integration_id : str, optional
            External integration identifier to associate.
        display_name : str, optional
            Human-readable name for the resource.
        **kwargs
            Extra keyword arguments ignored by the stub.

        Returns
        -------
        dict
            Engine-like response with 'status' and 'error' keys.
        """
        try:
            meta = {
                "name": display_name,
                "integration_id": integration_id
            }
            save_asset_file(_meta_path(policy_type, name), json.dumps(meta))
        except Exception:
            pass
        return {'status': 'OK', 'error': None}

    async def get_resources(self, type, name_list, policy_type: PolicyType, **kwargs) -> dict:
        """List content resources from disk, enriching with sidecar metadata if present.

        Parameters
        ----------
        type
            Resource type filter (e.g., KVDB).
        name_list : list
            Optional list of resource IDs to include.
        policy_type : PolicyType
            Policy scope to read from (TESTING/PRODUCTION).
        **kwargs
            Extra keyword arguments ignored by the stub.

        Returns
        -------
        dict
            Response with 'status', 'error' and 'content' (list of resources).
        """
        base = _base_dir(policy_type)
        items = []
        if os.path.isdir(base):
            for fname in os.listdir(base):
                if not fname.endswith('.json'):
                    continue
                rid = fname[:-5]
                if name_list and rid not in name_list:
                    continue
                try:
                    with open(os.path.join(base, fname), 'r') as f:
                        content = json.load(f)
                except Exception:
                    content = {}

                meta_name = None
                meta_integration = None
                try:
                    mpath = _meta_path(policy_type, rid)
                    if os.path.exists(mpath):
                        with open(mpath, 'r') as mf:
                            m = json.load(mf)
                            meta_name = m.get('name')
                            meta_integration = m.get('integration_id')
                except Exception:
                    pass

                items.append({
                    "type": ResourceType.KVDB.value,
                    "id": rid,
                    "name": meta_name,                  # <-- ya no será null si hay meta
                    "integration_id": meta_integration, # <-- idem
                    "content": content
                })
        return {"status": "OK", "error": None, "content": items}

    async def update_resource(
        self,
        name: str,
        content: str,
        policy_type: PolicyType,
        display_name: Optional[str] = None,
        **kwargs
    ) -> dict:
        """Update a content resource and optionally refresh its sidecar display name.

        Parameters
        ----------
        name : str
            Resource identifier to update.
        content : str
            New resource payload serialized as string.
        policy_type : PolicyType
            Policy scope where the resource resides.
        display_name : str, optional
            New human-readable name to persist in metadata.
        **kwargs
            Extra keyword arguments ignored by the stub.

        Returns
        -------
        dict
            Engine-like response with 'status' and 'error' keys.
        """
        if display_name is not None:
            try:
                mpath = _meta_path(policy_type, name)
                meta = {}
                if os.path.exists(mpath):
                    try:
                        with open(mpath, 'r') as mf:
                            meta = json.load(mf)
                    except Exception:
                        meta = {}
                meta['name'] = display_name
                if 'integration_id' not in meta:
                    meta['integration_id'] = None
                save_asset_file(mpath, json.dumps(meta))
            except Exception:
                pass
        return {'status': 'OK', 'error': None}

    async def delete_resource(
        self,
        name: str,
        policy_type: PolicyType,
        **kwargs
    ) -> dict:
        """Delete a content resource's sidecar metadata file if present.

        Parameters
        ----------
        name : str
            Resource identifier to delete metadata for.
        policy_type : PolicyType
            Policy scope where the resource resides.
        **kwargs
            Extra keyword arguments ignored by the stub.

        Returns
        -------
        dict
            Engine-like response with 'status' and 'error' keys.
        """
        try:
            mpath = _meta_path(policy_type, name)
            if os.path.exists(mpath):
                os.remove(mpath)
        except Exception:
            pass
        return {'status': 'OK', 'error': None}
