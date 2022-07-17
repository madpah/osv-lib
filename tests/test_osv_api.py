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
import datetime
from unittest import TestCase, mock
from unittest.mock import Mock

# See https://github.com/package-url/packageurl-python/issues/65
from packageurl import PackageURL  # type: ignore

from osv.api import OsvApi
from osv.model import OsvPackage, OsvSeverityType, OsvVulnerability, OsvVulnerabilityId

from .mocks import mock_osv_post_query


class TestOsvApi(TestCase):

    @mock.patch('requests.post', side_effect=mock_osv_post_query)
    def test_query_with_response(self, mock_post: Mock) -> None:
        api = OsvApi()
        vulnerabilities = api.query(package=OsvPackage(purl=PackageURL.from_string('pkg:npm/minimist@0.0.8')))
        mock_post.assert_called()
        self.assertEqual(2, len(vulnerabilities))

        vuln_984h = next((v for v in vulnerabilities if v.id_ == OsvVulnerabilityId('GHSA-xvch-5gv4-984h')), None)
        self.assertIsInstance(vuln_984h, OsvVulnerability)
        self.assertEqual(OsvVulnerabilityId('GHSA-xvch-5gv4-984h'), vuln_984h.id_)
        self.assertEqual(
            datetime.datetime(year=2022, month=4, day=4, hour=21, minute=39, second=38),
            vuln_984h.modified
        )
        self.assertEqual(
            datetime.datetime(year=2022, month=3, day=18, hour=0, minute=1, second=9),
            vuln_984h.published
        )
        self.assertIsNone(vuln_984h.withdrawn)
        self.assertEqual(1, len(vuln_984h.aliases))
        self.assertSetEqual({OsvVulnerabilityId('CVE-2021-44906')}, vuln_984h.aliases)
        self.assertEqual(0, len(vuln_984h.related))
        self.assertEqual('Prototype Pollution in minimist', vuln_984h.summary)
        self.assertEqual(
            'Minimist <=1.2.5 is vulnerable to Prototype Pollution via file index.js, function setKey()',
            vuln_984h.details)
        self.assertEqual(1, len(vuln_984h.severity))
        severity = vuln_984h.severity.pop()
        self.assertEqual(OsvSeverityType.CVSS_V3, severity.type_)
        self.assertEqual('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', severity.score)
        self.assertEqual(1, len(vuln_984h.affected))
        self.assertEqual(7, len(vuln_984h.references))
        self.assertEqual(0, len(vuln_984h.credits))
