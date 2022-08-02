# This file is part of osv-lib.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) Paul Horton. All Rights Reserved.

import json
import logging
import sys
from typing import Any, Dict, Iterable, Optional, Set, Union

import requests

from .exception import InvalidQueryParametersException, OsvApiErrorResponseException
from .model import OsvPackage, OsvVulnerability, OsvVulnerabilityId
from .serializer import OsvJsonEncoder

logger = logging.getLogger('osv-lib')

if sys.version_info >= (3, 8):
    from importlib.metadata import version as meta_version
else:
    from importlib_metadata import version as meta_version

osv_lib_version: str = 'TBC'
try:
    osv_lib_version = str(meta_version('osv-lib'))  # type: ignore[no-untyped-call]
except Exception:
    osv_lib_version = 'DEVELOPMENT'


class OsvApi:
    """
    API client wrapper to OSV.dev.

    See https://osv.dev/docs/#section/OSV-API
    """

    _api_version: str = 'v1'
    _api_host: str = 'https://api.osv.dev'
    _api_batch_query_maximum_packages: int = 1000

    def __init__(self) -> None:
        pass

    def query(self, *, commit: Optional[str] = None, version: Optional[str] = None,
              package: Optional[OsvPackage] = None) -> Set[OsvVulnerability]:
        """
        Implementation for POST /v1/query

        See https://osv.dev/docs/#operation/OSV_QueryAffected

        Returns:
            `Set[OsvVulnerability]`
        """
        api_url = self._get_api_url('query')
        response = requests.post(
            url=api_url, headers=self._get_headers(),
            json=OsvApi._make_query_payload(commit=commit, version=version, package=package)
        )

        if not response.status_code == 200:
            raise OsvApiErrorResponseException(
                f'OSV API returned {response.status_code} for call to {api_url}: {response.text}'
            )

        vulnerabilities: Set[OsvVulnerability] = set()
        if 'vulns' in response.json():
            for vuln_data in response.json()['vulns']:
                vulnerabilities.add(OsvVulnerability.from_json(data=vuln_data))

        return vulnerabilities

    def query_batch(self, *,
                    queries: Iterable[Dict[str, Union[Optional[str], Optional[OsvPackage]]]],
                    fully_hydrate: bool = False) -> Set[OsvVulnerability]:
        """
        Implementation for POST /v1/querybatch

        https://osv.dev/docs/#operation/OSV_QueryAffectedBatch

        Returns:
            `Set[OsvVulnerability]`
        """
        request_payload = []
        for query in queries:
            request_payload.append(OsvApi._make_query_payload(**query))  # type: ignore

        api_url = self._get_api_url('querybatch')
        response = requests.post(url=api_url, headers=self._get_headers(), json={"queries": request_payload})

        if not response.status_code == 200:
            raise OsvApiErrorResponseException(
                f'OSV API returned {response.status_code} for call to {api_url}: {response.text}'
            )

        vulnerabilities: Set[OsvVulnerability] = set()
        if 'results' in response.json():
            for vuln_data in response.json()['results']:
                if 'vulns' in vuln_data:
                    for vuln in vuln_data['vulns']:
                        osv_vulnerability = OsvVulnerability.from_json(data=vuln)
                        if fully_hydrate:
                            vulnerabilities.add(self.vulns(id_=osv_vulnerability.id_))
                        else:
                            vulnerabilities.add(osv_vulnerability)

        return vulnerabilities

    def vulns(self, *, id_: Union[str, OsvVulnerabilityId]) -> OsvVulnerability:
        """
        Implementation for POST /v1/vulns

        See: https://osv.dev/docs/#operation/OSV_GetVulnById

        Returns:
            `OsvVulnerability`
        """
        api_url = self._get_api_url(f'vulns/{str(id_)}')
        response = requests.get(url=api_url, headers=self._get_headers())

        if not response.status_code == 200:
            raise OsvApiErrorResponseException(
                f'OSV API returned {response.status_code} for call to {api_url}: {response.text}'
            )

        return OsvVulnerability.from_json(data=response.json())

    def _get_api_url(self, api_uri: str) -> str:
        return f'{self._api_host}/{self._api_version}/{api_uri}'

    @staticmethod
    def _get_headers() -> Dict[str, str]:
        return {
            'Accept': 'application/json',
            'Content-type': 'application/json',
            'User-Agent': f'python-osv-lib@{osv_lib_version}'
        }

    @staticmethod
    def _make_query_payload(*, commit: Optional[str] = None, version: Optional[str] = None,
                            package: Optional[OsvPackage] = None) -> Dict[str, Any]:
        if 0 == sum(x is not None for x in (commit, version, package)):
            raise InvalidQueryParametersException('At least one of `commit`, `version` or `package` is required.')

        if commit and version:
            raise InvalidQueryParametersException('If `commit` is supplied `version` cannot also be supplied.')

        request_data = {}
        if commit:
            request_data.update({'commit': commit})
        if version:
            request_data.update({'version': version})
        if package:
            request_data.update({'package': json.loads(json.dumps(package, cls=OsvJsonEncoder))})

        return request_data
