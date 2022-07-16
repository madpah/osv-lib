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
from typing import Dict, Iterable, List, Optional, Set, Union

import requests
# See https://github.com/package-url/packageurl-python/issues/65
from packageurl import PackageURL  # type: ignore

from exception import InvalidQueryParameters, OsvApiErrorResponse
from serializer import OsvJsonEncoder
from .model import OsvPackage, OsvVulnerability, OsvVulnerabilityId

# from .serializer import json_decoder, OssIndexJsonEncoder

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
        if 0 == sum(x is not None for x in (commit, version, package)):
            raise InvalidQueryParameters('At least one of `commit`, `version` or `package` is required.')

        if commit and version:
            raise InvalidQueryParameters('If `commit` is supplied `version` cannot also be supplied.')

        request_data = {}
        if commit:
            request_data.update({'commit': commit})
        if version:
            request_data.update({'version': version})
        if package:
            request_data.update({'package': json.loads(json.dumps(package, cls=OsvJsonEncoder))})

        api_url = self._get_api_url('query')
        response = requests.post(url=api_url, headers=self._get_headers(), json=request_data)

        if not response.status_code == 200:
            raise OsvApiErrorResponse(
                f'OSV API returned {response.status_code} for call to {api_url}: {response.json()}'
            )

        vulnerabilities: Set[OsvVulnerability] = set()
        for vuln_data in response.json()['vulns']:
            vulnerabilities.add(OsvVulnerability.from_json(data=vuln_data))

        return vulnerabilities

    def query_batch(self, *, packages: Iterable[OsvPackage]) -> None:
        pass

    def vulns(self, *, id_: Union[str, OsvVulnerabilityId]) -> None:
        pass

    ###
    ###
    ###
    ###

    # def get_component_report(self, packages: List[PackageURL]) -> List[OssIndexComponent]:
    #     logger.debug('A total of {} Packages to be queried against OSS Index'.format(len(packages)))
    #     return self._get_results(packages=packages)
    #
    # def purge_local_cache(self) -> None:
    #     if self._caching_enabled:
    #         logger.info('Truncating local cache database as requested')
    #         with self._get_cache_db() as db:
    #             db.truncate()
    #             logger.info('Local OSS Index cache has been purged')
    #
    # def _chunk_packages_for_oss_index(self, packages: List[PackageURL]) -> List[List[PackageURL]]:
    #     """
    #     Splits up the list of packages into lists that are of a size consumable by OSS Index
    #     APIs.
    #
    #     :param packages: List[PackageURL]
    #     :return: List[List[PackageURL]]
    #     """
    #     return list(
    #         [packages[i: i + self._oss_max_coordinates_per_request] for i in
    #          range(0, len(packages), self._oss_max_coordinates_per_request)]
    #     )

    def _get_api_url(self, api_uri: str) -> str:
        return f'{self._api_host}/{self._api_version}/{api_uri}'

    @staticmethod
    def _get_headers() -> Dict[str, str]:
        return {
            'Accept': 'application/json',
            'Content-type': 'application/json',
            'User-Agent': f'python-osv-lib@{osv_lib_version}'
        }

    # def _get_results(self, packages: List[PackageURL]) -> List[OssIndexComponent]:
    #     results: List[OssIndexComponent] = list()
    #
    #     # First get any cached results
    #     if self._caching_enabled:
    #         logger.debug('Checking local cache for any usable results...')
    #         packages, results = self._get_cached_results(packages=packages)
    #         logger.debug('   {} cached results found leaving {} to ask OSS Index'.format(
    #             len(results), len(packages)
    #         ))
    #
    #     # Second, chunk up packages for which we have no cached results and query OSS Index
    #     chunk: List[PackageURL]
    #     chunks = self._chunk_packages_for_oss_index(packages=packages)
    #     logger.debug('Split {} packages into {} chunks for OSS requests'.format(len(packages), len(chunks)))
    #     for chunk in chunks:
    #         logger.debug('  Getting chunk results from OSS Index...')
    #         results = results + self._make_oss_index_component_report_call(packages=chunk)
    #
    #     logger.debug('Total of {} results (including cached)'.format(len(results)))
    #     return results
    #
    # def _make_oss_index_component_report_call(self, packages: List[PackageURL]) -> List[OssIndexComponent]:
    #     response = requests.post(
    #         url=self._get_api_url('component-report'),
    #         headers=self._get_headers(),
    #         json={
    #             'coordinates': list(map(lambda p: str(p.to_string()), packages))
    #         },
    #         auth=self._oss_index_authentication
    #     )
    #
    #     if not response.status_code == 200:
    #         raise AccessDeniedException()
    #
    #     results: List[OssIndexComponent] = []
    #     for oic in response.json(object_hook=json_decoder):
    #         results.append(oic)
    #
    #     if self._caching_enabled:
    #         self._upsert_cache_with_oss_index_responses(oss_components=results)
    #     return results
