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
import json
import os
from unittest import TestCase

from osv.model import OsvSeverityType, OsvVulnerability, OsvVulnerabilityId

from . import FIXTURES_DIRECTORY


class TestDeserialisation(TestCase):

    def test_vulnerability_simple(self) -> None:
        v = OsvVulnerability.from_json(data=json.loads(
            '{ "id": "GHSA-vh95-rmgr-6w4m", "summary": "Prototype Pollution in minimist", '
            '"modified": "2022-04-26T21:01:40Z", "aliases": [ "CVE-2020-7598"] }'
        ))
        self.assertIsInstance(v, OsvVulnerability)
        self.assertEqual('Prototype Pollution in minimist', v.summary)
        self.assertEqual(OsvVulnerabilityId('GHSA-vh95-rmgr-6w4m'), v.id_)
        self.assertEqual(1, len(v.aliases))
        self.assertSetEqual({OsvVulnerabilityId('CVE-2020-7598')}, v.aliases)

    def test_vulnerability_example_1(self) -> None:
        with open(os.path.join(FIXTURES_DIRECTORY, 'GHSA-vh95-rmgr-6w4m.json'), 'r') as vuln_f:
            v = OsvVulnerability.from_json(data=json.loads(vuln_f.read()))
            self.assertIsInstance(v, OsvVulnerability)
            self.assertEqual(OsvVulnerabilityId('GHSA-vh95-rmgr-6w4m'), v.id_)
            self.assertEqual(
                datetime.datetime(year=2022, month=4, day=26, hour=21, minute=1, second=40),
                v.modified
            )
            self.assertEqual(
                datetime.datetime(year=2020, month=4, day=3, hour=21, minute=48, second=32),
                v.published
            )
            self.assertIsNone(v.withdrawn)
            self.assertEqual(1, len(v.aliases))
            self.assertSetEqual({OsvVulnerabilityId('CVE-2020-7598')}, v.aliases)
            self.assertEqual(0, len(v.related))
            self.assertEqual('Prototype Pollution in minimist', v.summary)
            self.assertEqual("""Affected versions of `minimist` are vulnerable to prototype pollution. Arguments are not properly sanitized, allowing an attacker to modify the prototype of `Object`, causing the addition or modification of an existing property that will exist on all objects.  
Parsing the argument `--__proto__.y=Polluted` adds a `y` property with value `Polluted` to all objects. The argument `--__proto__=Polluted` raises and uncaught error and crashes the application.  
This is exploitable if attackers have control over the arguments being passed to `minimist`.



## Recommendation

Upgrade to versions 0.2.1, 1.2.3 or later.""", v.details)
            self.assertEqual(1, len(v.severity))
            severity = v.severity.pop()
            self.assertEqual(OsvSeverityType.CVSS_V3, severity.type_)
            self.assertEqual('CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L', severity.score)
            self.assertEqual(2, len(v.affected))
            self.assertEqual(8, len(v.references))
            self.assertEqual(0, len(v.credits))
