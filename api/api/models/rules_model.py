# coding: utf-8

from __future__ import absolute_import
from datetime import date, datetime  # noqa: F401

from typing import List, Dict  # noqa: F401

from api.models.base_model_ import Model
from api.models.rules_files_model import RulesFiles
from api import util


class Rules(Model):

    def __init__(self, rules_files: RulesFiles=None, id: int=None,
                 level: int=None, description: str=None, 
                 groups: List[str]=None, pci: List[str]=None,
                 gdpr: List[str]=None, details: Dict[str,str]=None):
        """Rules body model
        :param rules_files: 
        :type RulesFiles: RulesFiles
        :param id:
        :type id: int
        :param level: 
        :type level: int
        :param description:
        :type description: int
        :param groups:
        :type groups: List[str]
        :param pci:
        :type pci: List[str]
        :param gdpr:
        :type gdpr: List[str]
        :param details:
        :type details: Dict
        """
        self.swagger_types = {
            'rules_files': RulesFiles,
            'id': int,
            'level': int,
            'description': str,
            'groups': List[str],
            'pci': List[str],
            'gdpr': List[str],
            'details': Dict[str,str]
        }

        self.attribute_map = {
            'rules_files': 'rules_files',
            'id': 'id',
            'level': 'level',
            'description': 'description',
            'groups': 'groups',
            'pci': 'pci',
            'gdpr': 'gdpr',
            'details': 'details'
        }

        self._rules_files = rules_files
        self._id = id
        self._level = level
        self._description = description
        self._groups = groups
        self._pci = pci
        self._gdpr = gdpr
        self._details = details

    @classmethod
    def from_dict(cls, dikt) -> Dict:
        """Returns the dict as a model
        :param dikt: A dict.
        :type: dict
        :return: The Agent of this Agent.
        :rtype: dict
        """
        return util.deserialize_model(dikt, cls)

    @property
    def rules_files(self) -> RulesFiles:
        """
        :return: 
        :rtype: RulesFiles
        """
        return self._rules_files

    @rules_files.setter
    def rules_files(self, rules_files: RulesFiles):
        """Error code
        :param rules_files:
        """
        self._rules_files = rules_files

    @property
    def id(self) -> int:
        """
        :return: Details 
        :rtype: str
        """
        return self._id

    @id.setter
    def id(self, id: int):
        """
        :param id: Details 
        """
        self._id = id

    @property
    def level(self) -> int:
        """
        :return: Details 
        :rtype: str
        """
        return self._level

    @level.setter
    def level(self, level: int):
        """
        :param level: Details 
        """
        self._level = level

    @property
    def description(self) -> str:
        """
        :return: Details 
        :rtype: str
        """
        return self._description

    @description.setter
    def description(self, description: str):
        """
        :param description: Details 
        """
        self._description = description
    
    @property
    def groups(self) -> str:
        """
        :return: Details 
        :rtype: str
        """
        return self._groups

    @groups.setter
    def groups(self, groups: str):
        """
        :param groups: Details 
        """
        self._groups = groups

    @property
    def pci(self) -> List[str]:
        """
        :return: Details 
        :rtype: str
        """
        return self._pci

    @pci.setter
    def pci(self, pci: List[str]):
        """
        :param pci: Details 
        """
        self._pci = pci

    @property
    def gdpr(self) -> List[str]:
        """
        :return: Details 
        :rtype: str
        """
        return self._gdpr

    @gdpr.setter
    def gdpr(self, gdpr: List[str]):
        """
        :param gdpr: Details
        """
        self._gdpr = gdpr

    @property
    def details(self) -> Dict[str,str]:
        """
        :return: Details
        :rtype: str
        """
        return self._details

    @details.setter
    def details(self, details: Dict[str,str]):
        """
        :param details: Details 
        """
        self._details = details

