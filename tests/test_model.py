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
from unittest import TestCase

from osv.exception import InvalidAffectedRange
from osv.model import OsvEcosystem, OsvPackage, OsvVersionRange, OsvVersionRangeType, OsvVulnerabilityId


class TestModelOsvVersionRange(TestCase):

    def test_invalid_type_single_event(self) -> None:
        with self.assertRaises(InvalidAffectedRange):
            OsvVersionRange.from_json(
                data=json.loads('{"events": [{ "introduced": "1.0.0" }, { "fixed": "1.2.3" } ], "type": "WRONG"}')
            )

    def test_semver_single_event(self) -> None:
        vr = OsvVersionRange.from_json(
            data=json.loads('{"events": [{ "introduced": "1.0.0" } ], "type": "SEMVER"}')
        )
        self.assertEqual(vr.type_, OsvVersionRangeType.SEMVER)
        self.assertEqual(len(vr.events), 1)
        self.assertEqual(vr.as_purl_vers(), 'vers:semver/>=1.0.0')

    def test_semver_single_range(self) -> None:
        vr = OsvVersionRange.from_json(
            data=json.loads('{"events": [{ "introduced": "1.0.0" }, { "fixed": "1.2.3" } ], "type": "SEMVER"}')
        )
        self.assertEqual(vr.type_, OsvVersionRangeType.SEMVER)
        self.assertEqual(len(vr.events), 2)
        self.assertEqual(vr.as_purl_vers(), 'vers:semver/>=1.0.0|<1.2.3')

    def test_semver_two_ranges(self) -> None:
        vr = OsvVersionRange.from_json(
            data=json.loads('{"events": [{ "introduced": "1.0.0" }, { "fixed": "1.2.3" }, { "introduced": "2.0.0" }, '
                            '{ "fixed": "2.0.5" } ], "type": "SEMVER"}')
        )
        self.assertEqual(vr.type_, OsvVersionRangeType.SEMVER)
        self.assertEqual(len(vr.events), 4)
        self.assertEqual(vr.as_purl_vers(), 'vers:semver/>=1.0.0|<1.2.3|>=2.0.0|<2.0.5')

    def test_semver_single_range_last_affected(self) -> None:
        vr = OsvVersionRange.from_json(
            data=json.loads('{"events": [{ "introduced": "1.0.0" }, { "last_affected": "1.2.3" } ], "type": "SEMVER"}')
        )
        self.assertEqual(vr.type_, OsvVersionRangeType.SEMVER)
        self.assertEqual(len(vr.events), 2)
        self.assertEqual(vr.as_purl_vers(), 'vers:semver/>=1.0.0|<=1.2.3')

    def test_ecosystem_single_range_no_package(self) -> None:
        vr = OsvVersionRange.from_json(
            data=json.loads('{"events": [{ "introduced": "1.14.0" }, { "last_affected": "2.1.0" } ], '
                            '"type": "ECOSYSTEM"}')
        )
        self.assertEqual(vr.type_, OsvVersionRangeType.ECOSYSTEM)
        self.assertEqual(len(vr.events), 2)
        self.assertEqual(vr.as_purl_vers(), 'vers:ecosystem/>=1.14.0|<=2.1.0')

    def test_ecosystem_single_range_package(self) -> None:
        vr = OsvVersionRange.from_json(
            data=json.loads('{"events": [{ "introduced": "1.14.0" }, { "last_affected": "2.1.0" } ], '
                            '"type": "ECOSYSTEM"}')
        )
        self.assertEqual(vr.type_, OsvVersionRangeType.ECOSYSTEM)
        self.assertEqual(len(vr.events), 2)
        self.assertIsNone(vr.repo)
        self.assertEqual(
            vr.as_purl_vers(package=OsvPackage(ecosystem=OsvEcosystem.PYPI, name='Something')),
            'vers:pypi/>=1.14.0|<=2.1.0'
        )

    def test_git_single_range(self) -> None:
        vr = OsvVersionRange.from_json(
            data=json.loads('{ "type": "GIT", "repo": "https://github.com/unicode-org/icu.git", "events": [ '
                            '{ "introduced": "6e5755a2a833bc64852eae12967d0a54d7adf629" }, '
                            '{ "fixed": "c43455749b914feef56b178b256f29b3016146eb" } ] }')
        )
        self.assertEqual(vr.type_, OsvVersionRangeType.GIT)
        self.assertEqual(len(vr.events), 2)
        self.assertEqual(vr.repo, 'https://github.com/unicode-org/icu.git')
        self.assertEqual(
            vr.as_purl_vers(),
            'vers:git/>=6e5755a2a833bc64852eae12967d0a54d7adf629|<c43455749b914feef56b178b256f29b3016146eb'
        )


class TestModelOsvVulnerabilityId(TestCase):

    def test_go_1(self) -> None:
        v = OsvVulnerabilityId('GO-2020-0001')
        self.assertEqual(v.db_prefix, 'GO')
        self.assertEqual(v.entry_id, '2020-0001')
        self.assertTrue(v.is_from_known_database())

    def test_go_2(self) -> None:
        v = OsvVulnerabilityId('go-2020-0001')
        self.assertEqual(v.db_prefix, 'GO')
        self.assertEqual(v.entry_id, '2020-0001')
        self.assertTrue(v.is_from_known_database())

    def test_osv_1(self) -> None:
        v = OsvVulnerabilityId('OsV-2022-580')
        self.assertEqual(v.db_prefix, 'OSV')
        self.assertEqual(v.entry_id, '2022-580')
        self.assertTrue(v.is_from_known_database())

    def test_dsa_1(self) -> None:
        v = OsvVulnerabilityId('DSA-5087-1')
        self.assertEqual(v.db_prefix, 'DSA')
        self.assertEqual(v.entry_id, '5087-1')
        self.assertFalse(v.is_from_known_database())
