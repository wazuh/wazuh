# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from api.models.base_model_ import Model
from api.models.scan_id_time import ScanIdTime
from api import util


class CiscatResults(Model):

    def __init__(self, profile: str = None, score: int = None, error: int = None, scan: ScanIdTime = None,
                 fail: int = None, benchmark: str = None, passed: int = None, notchecked: int = None,
                 unknown: int = None):
        """CiscatResults - a model defined in Swagger

        :param profile: CIS-CAT profile scanned.
        :param score: Percentage of passed checks.
        :param error: Number of checks that CIS-CAT wasn't able to run.
        :param scan: Scan
        :param fail: Number of failed checks. If this number is higher than 0 the host will probably have a
                     vulnerability.
        :param benchmark: CIS-CAT benchmark where the profile is defined.
        :param passed: Number of passed checks.
        :param notchecked: Number of not passed checks.
        :param unknown: Number of checks which status CIS-CAT wasn't able to determine.
        """
        self.swagger_types = {
            'profile': str,
            'score': int,
            'error': int,
            'scan': ScanIdTime,
            'fail': int,
            'benchmark': str,
            'passed': int,
            'notchecked': int,
            'unknown': int
        }

        self.attribute_map = {
            'profile': 'profile',
            'score': 'score',
            'error': 'error',
            'scan': 'scan',
            'fail': 'fail',
            'benchmark': 'benchmark',
            'passed': 'passed',
            'notchecked': 'notchecked',
            'unknown': 'unknown'
        }

        self._profile = profile
        self._score = score
        self._error = error
        self._scan = scan
        self._fail = fail
        self._benchmark = benchmark
        self._passed = passed
        self._notchecked = notchecked
        self._unknown = unknown

    @classmethod
    def from_dict(cls, dikt) -> 'CiscatResults':
        """Returns the dict as a model

        :param dikt: A dict.
        :return: The CiscatResults of this CiscatResults.
        """
        return util.deserialize_model(dikt, cls)

    @property
    def profile(self) -> str:
        """Gets the profile of this CiscatResults

        :return: The profile of this CiscatResults
        """
        return self._profile

    @profile.setter
    def profile(self, profile: str):
        """Sets the profile of this CiscatResults

        :param profile: The profile of this CiscatResults
        """
        self._profile = profile

    @property
    def score(self) -> int:
        """Gets the score of this CiscatResults

        :return: The score of this CiscatResults
        """
        return self._score

    @score.setter
    def score(self, score: int):
        """Sets the score of this CiscatResults

        :param score: The score of this CiscatResults
        """
        self._score = score

    @property
    def error(self) -> int:
        """Gets the error of this CiscatResults

        :return: The error of this CiscatResults
        """
        return self._error

    @error.setter
    def error(self, error: int):
        """Sets the error of this CiscatResults

        :param error: The error of this CiscatResults
        """
        self._error = error

    @property
    def scan(self) -> ScanIdTime:
        """Gets the scan of this CiscatResults

        :return: The scan of this CiscatResults
        """
        return self._scan

    @scan.setter
    def scan(self, scan: ScanIdTime):
        """Sets the scan of this CiscatResults

        :param scan: The scan of this CiscatResults
        """
        self._scan = scan

    @property
    def fail(self) -> int:
        """Gets the fail of this CiscatResults

        :return: The fail of this CiscatResults
        """
        return self._fail

    @fail.setter
    def fail(self, fail: int):
        """Sets the fail of this CiscatResults

        :param fail: The fail of this CiscatResults
        """
        self._fail = fail

    @property
    def benchmark(self) -> str:
        """Gets the benchmark of this CiscatResults

        :return: The benchmark of this CiscatResults
        """
        return self._benchmark

    @benchmark.setter
    def benchmark(self, benchmark: str):
        """Sets the benchmark of this CiscatResults

        :param benchmark: The benchmark of this CiscatResults
        """
        self._benchmark = benchmark

    @property
    def passed(self) -> int:
        """Gets the passed of this CiscatResults

        :return: The passed of this CiscatResults
        """
        return self._passed

    @passed.setter
    def passed(self, passed: int):
        """Sets the passed of this CiscatResults

        :param passed: The passed of this CiscatResults
        """
        self._passed = passed

    @property
    def notchecked(self) -> int:
        """Gets the notchecked of this CiscatResults

        :return: The notchecked of this CiscatResults
        """
        return self._notchecked

    @notchecked.setter
    def notchecked(self, notchecked: int):
        """Sets the notchecked of this CiscatResults

        :param notchecked: The notchecked of this CiscatResults
        """
        self._notchecked = notchecked

    @property
    def unknown(self) -> int:
        """Gets the unknown of this CiscatResults

        :return: The unknown of this CiscatResults
        """
        return self._unknown

    @unknown.setter
    def unknown(self, unknown: int):
        """Sets the unknown of this CiscatResults

        :param unknown: The unknown of this CiscatResults
        """
        self._unknown = unknown
