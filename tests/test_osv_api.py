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
from osv.model import (
    OsvAffected,
    OsvPackage,
    OsvSchemaVersion,
    OsvSeverityType,
    OsvVersionRange,
    OsvVersionRangeType,
    OsvVulnerability,
    OsvVulnerabilityId,
)
from tests.mocks import mock_osv_get_vulns, mock_osv_post_query, mock_osv_post_query_batch


class TestOsvApi(TestCase):

    @mock.patch('requests.get', side_effect=mock_osv_get_vulns)
    def test_vulns_with_response_1(self, mock_get: Mock) -> None:
        api = OsvApi()
        vulnerability = api.vulns(id_='OSV-2020-111')
        mock_get.assert_called()

        self.assertIsInstance(vulnerability, OsvVulnerability)
        self.assertEqual(OsvVulnerabilityId('OSV-2020-111'), vulnerability.id_)
        self.assertEqual(
            datetime.datetime(year=2021, month=3, day=9, hour=4, minute=49, second=5, microsecond=94973),
            vulnerability.modified
        )
        self.assertEqual(
            datetime.datetime(year=2020, month=6, day=24, hour=1, minute=51, second=14, microsecond=570467),
            vulnerability.published
        )
        self.assertIsNone(vulnerability.withdrawn)
        self.assertEqual(0, len(vulnerability.aliases))
        self.assertEqual(0, len(vulnerability.related))
        self.assertEqual("Heap-use-after-free in int std::__1::__cxx_atomic_fetch_sub<int>", vulnerability.summary)
        self.assertEqual(
            'OSS-Fuzz report: https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=21604',
            vulnerability.details)
        self.assertEqual(0, len(vulnerability.severity))
        self.assertEqual(1, len(vulnerability.affected))

        affected_1 = vulnerability.affected.pop()
        self.assertIsInstance(affected_1, OsvAffected)
        self.assertIsInstance(affected_1.package, OsvPackage)
        self.assertEqual(affected_1.package.ecosystem, 'OSS-Fuzz')
        self.assertEqual(affected_1.package.name, 'poppler')
        self.assertEqual(affected_1.package.purl, 'pkg:generic/poppler')
        self.assertEqual(1, len(affected_1.ranges))
        range_1 = affected_1.ranges.pop()
        self.assertIsInstance(range_1, OsvVersionRange)
        self.assertEqual(range_1.type_, OsvVersionRangeType.GIT)
        self.assertEqual(range_1.repo, 'https://anongit.freedesktop.org/git/poppler/poppler.git')
        self.assertListEqual(range_1.events, [
            OsvVersionRange.OsvVersionRangeEvent(introduced='e4badf4d745b8e8f9a0a25b6c3cc97fbadbbb499'),
            OsvVersionRange.OsvVersionRangeEvent(fixed='155f73bdd261622323491df4aebb840cde8bfee1')
        ])

        self.assertEqual(1, len(vulnerability.references))
        self.assertEqual(0, len(vulnerability.credits))
        self.assertEqual(OsvSchemaVersion.V1_2_0, vulnerability.schema_version)

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

    @mock.patch('requests.post', side_effect=mock_osv_post_query_batch)
    def test_query_batch_with_response(self, mock_post: Mock) -> None:
        api = OsvApi()
        queries = [
            {
                'package': OsvPackage(purl=PackageURL.from_string('pkg:npm/minimist@0.0.8'))
            }
        ]
        vulnerabilities = api.query_batch(queries=queries)
        mock_post.assert_called()

        self.assertEqual(1, len(vulnerabilities))
        expected_hash_key = hash(str(OsvApi._make_query_payload(**queries.pop())))
        self.assertTrue(expected_hash_key in vulnerabilities)
        vulns = vulnerabilities.get(expected_hash_key)

        vuln_6w4m = next((v for v in vulns if v.id_ == OsvVulnerabilityId('GHSA-vh95-rmgr-6w4m')), None)
        self.assertIsInstance(vuln_6w4m, OsvVulnerability)
        self.assertEqual(OsvVulnerabilityId('GHSA-vh95-rmgr-6w4m'), vuln_6w4m.id_)
        self.assertEqual(
            datetime.datetime(year=2022, month=4, day=26, hour=21, minute=1, second=40),
            vuln_6w4m.modified
        )

        vuln_984h = next((v for v in vulns if v.id_ == OsvVulnerabilityId('GHSA-xvch-5gv4-984h')), None)
        self.assertIsInstance(vuln_984h, OsvVulnerability)
        self.assertEqual(OsvVulnerabilityId('GHSA-xvch-5gv4-984h'), vuln_984h.id_)
        self.assertEqual(
            datetime.datetime(year=2022, month=4, day=4, hour=21, minute=39, second=38),
            vuln_984h.modified
        )
