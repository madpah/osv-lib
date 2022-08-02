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
import os
from typing import Callable, Optional

# See https://github.com/package-url/packageurl-python/issues/65
from packageurl import PackageURL  # type: ignore

from . import FIXTURES_DIRECTORY

OSV_API_BASE_URI = 'https://api.osv.dev/v1/'


class MockResponse:
    def __init__(self, data: Optional[str], status_code: int) -> None:
        self._text = data if data else ''
        self._status_code = status_code

    @property
    def status_code(self) -> int:
        return self._status_code

    @property
    def text(self) -> str:
        return self._text

    def json(self, object_hook: Optional[Callable] = None) -> object:
        return json.loads(self.text, object_hook=object_hook)


def mock_osv_get_vulns(*args, **kwargs) -> MockResponse:
    if 'url' in kwargs and str(kwargs['url']).startswith(f'{OSV_API_BASE_URI}vulns'):
        vulnerability_id = kwargs['url'].split('/')[-1]
        fixture = os.path.join(FIXTURES_DIRECTORY, f'response-vulns-{vulnerability_id}.json')
        return _mock_response_from_fixture(fixture=fixture)

    return MockResponse(None, 404)


def mock_osv_post_query(*args, **kwargs) -> MockResponse:
    if 'url' in kwargs and kwargs['url'] == f'{OSV_API_BASE_URI}query':
        request_json = kwargs['json'] if 'json' in kwargs else {}
        purl = PackageURL.from_string(purl=request_json['package']['purl'])
        fixture = os.path.join(FIXTURES_DIRECTORY, f'response-query-{purl.type}-{purl.name}-{purl.version}.json')

        return _mock_response_from_fixture(fixture=fixture)

    return MockResponse(None, 404)


def mock_osv_post_query_batch(*args, **kwargs) -> MockResponse:
    if 'url' in kwargs and kwargs['url'] == f'{OSV_API_BASE_URI}querybatch':
        request_json = kwargs['json'] if 'json' in kwargs else {}
        purl = PackageURL.from_string(purl=request_json['queries'][0]['package']['purl'])
        fixture = os.path.join(FIXTURES_DIRECTORY, f'response-querybatch-{purl.type}-{purl.name}-{purl.version}.json')

        return _mock_response_from_fixture(fixture=fixture)

    return MockResponse(None, 404)


def _mock_response_from_fixture(fixture: str) -> MockResponse:
    if os.path.exists(fixture):
        with open(fixture, 'r') as response_json_f:
            return MockResponse(response_json_f.read(), 200)
    else:
        return MockResponse(None, 500)
