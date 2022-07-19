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

import enum
import inspect
import re
from copy import copy
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Set, Type

# See https://github.com/package-url/packageurl-python/issues/65
from packageurl import PackageURL  # type: ignore

from .exception import (
    InvalidAffectedRangeException,
    InvalidDateException,
    InvalidVersionRangeEventException,
    InvalidVulnerabilityIdException,
)
from .serializer import JsonDeserialisable

"""
Pythonic model classes that represent the datastructures used in OSV.

.. see:
    https://osv.dev/docs/osv_service_v1.swagger.json

.. see:
    https://ossf.github.io/osv-schema/
    https://github.com/ossf/osv-schema/blob/main/validation/schema.json
"""

_PATTERN_DATE_TIME_RFC3339_Z = '%Y-%m-%dT%H:%M:%SZ'
_PATTERN_DATE_TIME_RFC3339_MS_Z = '%Y-%m-%dT%H:%M:%S.%fZ'
_PATTERN_VULNERABILITY_ID = re.compile(r'^([^\-]+)-(.*)')


def _deserialise_date(date_str: str) -> datetime:
    try:
        return datetime.strptime(date_str, _PATTERN_DATE_TIME_RFC3339_Z)
    except ValueError:
        try:
            return datetime.strptime(date_str, _PATTERN_DATE_TIME_RFC3339_MS_Z)
        except ValueError:
            raise InvalidDateException(f'Date string supplied ({date_str}) does not match either'
                                       f'"{_PATTERN_DATE_TIME_RFC3339_Z}" or "{_PATTERN_DATE_TIME_RFC3339_MS_Z}"')


@enum.unique
class OsvEcosystem(enum.Enum):
    """
    See https://ossf.github.io/osv-schema/#affectedpackage-field
    """
    ANDROID = 'Android'
    CRATES = 'crates.io'
    DEBIAN = 'Debian'
    GO = 'Go'
    HEX = 'Hex'
    LINUX = 'Linux'
    MAVEN = 'Maven'
    NPM = 'npm'
    NUGET = 'NuGet'
    OSS_FUZZ = 'OSS-Fuzz'
    PACKAGIST = 'Packagist'
    PYPI = 'PyPI'
    RUBY_GEMS = 'RubyGems'


@enum.unique
class OsvReferenceType(enum.Enum):
    """
    Reference Types

    `ADVISORY`: A published security advisory for the vulnerability.
    `ARTICLE`: An article or blog post describing the vulnerability.
    `REPORT`: A report, typically on a bug or issue tracker, of the vulnerability.
    `FIX`: A source code browser link to the fix (e.g., a GitHub commit) Note that the fix type is meant for viewing by
        people using web browsers. Programs interested in analyzing the exact commit range would do better to use the
        GIT-typed affected[].ranges entries (described above).
    `PACKAGE`: A home web page for the package.
    `EVIDENCE`: A demonstration of the validity of a vulnerability claim, e.g. app.any.run replaying the exploitation
        of the vulnerability.
    `WEB`: A web page of some unspecified kind.

    See https://ossf.github.io/osv-schema/#references-field

    """
    ADVISORY = 'ADVISORY'
    ARTICLE = 'ARTICLE'
    EVIDENCE = 'EVIDENCE'
    FIX = 'FIX'
    PACKAGE = 'PACKAGE'
    REPORT = 'REPORT'
    WEB = 'WEB'


@enum.unique
class OsvSchemaVersion(enum.Enum):
    V1_2_0 = '1.2.0'


DEFAULT_OSV_SCHEMA_VERSION = OsvSchemaVersion.V1_2_0


@enum.unique
class OsvSeverityType(enum.Enum):
    CVSS_V3 = 'CVSS_V3'


@enum.unique
class OsvVersionRangeType(enum.Enum):
    """
    See https://ossf.github.io/osv-schema/#affectedrangestype-field
    """
    ECOSYSTEM = 'ECOSYSTEM'
    GIT = 'GIT'
    SEMVER = 'SEMVER'


class OsvCredit:
    """
    A way to give credit for the discovery, confirmation, patch, or other events in the life cycle of a vulnerability.

    See https://ossf.github.io/osv-schema/#credits-fields
    """

    def __init__(self, *, name: str, contact: Optional[Iterable[str]] = None) -> None:
        self.name = name
        self.contact = contact or []  # type: ignore

    @property
    def name(self) -> str:
        """
        Should specify the name, label, or other identifier of the individual or entity being credited, using whatever
        notation the creditor prefers.

        For instance, this could contain a real name like `Kovács János`, an Internet handle like `erikamustermann`, an
        entity name like `GitHub`, or something else.

        Returns:
            `str`
        """
        return self._name

    @name.setter
    def name(self, name: str) -> None:
        self._name = name

    @property
    def contact(self) -> Set[str]:
        """
        Each contact entry should be a valid, fully qualified, plain-text URL at which the credited can be reached.

        Providing contacts is optional.

        Returns:
            `Set[str]`
        """
        return self._contact

    @contact.setter
    def contact(self, contact: Iterable[str]) -> None:
        self._contact = set(contact)


class OsvPackage:
    """
    See https://ossf.github.io/osv-schema/#affectedpackage-field
    """

    def __init__(self, *, ecosystem: Optional[OsvEcosystem] = None, name: Optional[str] = None,
                 purl: Optional[PackageURL] = None) -> None:
        self.ecosystem = ecosystem
        self.name = name
        self.purl = purl

    @property
    def ecosystem(self) -> Optional[OsvEcosystem]:
        """
        The ecosystem identifies the overall library ecosystem.

        Returns:
            `OsvEcosystem` or `None`
        """
        return self._ecosystem

    @ecosystem.setter
    def ecosystem(self, ecosystem: Optional[OsvEcosystem]) -> None:
        self._ecosystem = ecosystem

    @property
    def name(self) -> Optional[str]:
        """
        The name field is a string identifying the library within its ecosystem.

        Returns:
             `str` or `None`
        """
        return self._name

    @name.setter
    def name(self, name: Optional[str]) -> None:
        self._name = name

    @property
    def purl(self) -> Optional[PackageURL]:
        """
        purl as defined by Package URL specification.

        Returns:
            `Optional[PackageURL]`
        """
        return self._purl

    @purl.setter
    def purl(self, purl: Optional[PackageURL]) -> None:
        self._purl = purl


class OsvReference(JsonDeserialisable):
    """
    A reference.

    See https://ossf.github.io/osv-schema/#references-field
    """

    @staticmethod
    def from_json(data: Dict[str, Any]) -> 'OsvReference':
        return OsvReference(type_=OsvReferenceType(data['type']), url=data['url'])

    def __init__(self, *, type_: OsvReferenceType, url: str) -> None:
        self._type_ = type_
        self._url = url

    @property
    def type_(self) -> OsvReferenceType:
        """
        See `OsvReferenceType`.

        Returns:
            `OsvReferenceType`
        """
        return self._type_

    @property
    def url(self) -> str:
        """
        Fully qualified URL of the reference including scheme.

        Returns:
             `str`
        """
        return self._url


class OsvSeverity(JsonDeserialisable):

    def __init__(self, *, score: str, type_: OsvSeverityType) -> None:
        self.score = score
        self.type_ = type_

    @staticmethod
    def from_json(data: Dict[str, Any]) -> 'OsvSeverity':
        return OsvSeverity(score=data['score'], type_=OsvSeverityType(data['type']))

    @property
    def score(self) -> str:
        """
        A string representing the severity score based on the selected type.

        Returns:
            `str`
        """
        return self._score

    @score.setter
    def score(self, score: str) -> None:
        self._score = score

    @property
    def type_(self) -> OsvSeverityType:
        """
        One of the supported severity scoring types.

        Returns:
            `OsvSeverityType`
        """
        return self._type_

    @type_.setter
    def type_(self, type_: OsvSeverityType) -> None:
        self._type_ = type_


class OsvVersionRange:
    class OsvVersionRangeEvent:

        def __init__(self, *, introduced: Optional[str] = None, fixed: Optional[str] = None,
                     last_affected: Optional[str] = None, limit: Optional[str] = None) -> None:
            if 1 != sum(x is not None for x in (introduced, fixed, last_affected, limit)):
                raise InvalidVersionRangeEventException(
                    'affected[].ranges[].events[] can only contain a single event type'
                )
            self._introduced = introduced
            self._fixed = fixed
            self._last_affected = last_affected
            self._limit = limit

        @property
        def introduced(self) -> Optional[str]:
            """
            See https://ossf.github.io/osv-schema/#affectedrangesevents-fields

            Returns:
                 `str` or `None`
            """
            return self._introduced

        @property
        def fixed(self) -> Optional[str]:
            """
            See https://ossf.github.io/osv-schema/#affectedrangesevents-fields

            Returns:
                 `str` or `None`
            """
            return self._fixed

        @property
        def last_affected(self) -> Optional[str]:
            """
            See https://ossf.github.io/osv-schema/#affectedrangesevents-fields

            Returns:
                 `str` or `None`
            """
            return self._last_affected

        @property
        def limit(self) -> Optional[str]:
            """
            See https://ossf.github.io/osv-schema/#affectedrangesevents-fields

            Returns:
                 `str` or `None`
            """
            return self._limit

        def as_purl_vers_component(self) -> str:
            if self.introduced:
                return f'>={self.introduced}'
            if self.fixed:
                return f'<{self.fixed}'
            if self.last_affected:
                return f'<={self.last_affected}'

            return ''

        def __eq__(self, other: object) -> bool:
            if isinstance(other, OsvVersionRange.OsvVersionRangeEvent):
                return hash(other) == hash(self)

            return False

        def __hash__(self) -> int:
            return hash((self._introduced, self._fixed, self._last_affected, self._limit))

    @staticmethod
    def from_json(data: Dict[str, Any]) -> 'OsvVersionRange':
        if 'type' not in data:
            raise InvalidAffectedRangeException('"type" is a mandatory field for affected[].ranges[]')

        if 'events' not in data:
            raise InvalidAffectedRangeException('"events" is a mandatory field for affected[].ranges[]')

        try:
            type_ = OsvVersionRangeType(data['type'])
        except ValueError:
            raise InvalidAffectedRangeException(
                f'supplied value for "type" ({data["type"]}) is not a permitted value'
            )

        events: List["OsvVersionRange.OsvVersionRangeEvent"] = []
        for event in data['events']:
            events.append(OsvVersionRange.OsvVersionRangeEvent(**event))

        return OsvVersionRange(type_=type_, events=events, repo=data['repo'] if 'repo' in data else None)

    def __init__(self, *, type_: OsvVersionRangeType, events: List["OsvVersionRange.OsvVersionRangeEvent"],
                 repo: Optional[str] = None) -> None:
        self._type_ = type_
        self._events = events
        self._repo = repo

    @property
    def type_(self) -> OsvVersionRangeType:
        """
        See https://ossf.github.io/osv-schema/#affectedrangestype-field

        Returns:
             `OsvVersionRangeType`
        """
        return self._type_

    @property
    def events(self) -> List["OsvVersionRange.OsvVersionRangeEvent"]:
        """
        Set of events that represent a “timeline” of status changes for the affected package.

        See https://ossf.github.io/osv-schema/#affectedrangesevents-fields

        Returns:
            `List[OsvVersionRange.OsvVersionRangeEvent]`
        """
        return self._events

    @property
    def repo(self) -> Optional[str]:
        return self._repo

    def as_purl_vers(self, *, package: Optional[OsvPackage] = None) -> str:
        """
        This Version Range expressed Package URL Version Range syntax.

        See:  https://github.com/package-url/purl-spec/VERSION-RANGE-SPEC.rst

        Returns:
            `str`
        """
        vers_type = self.type_.value.lower()
        if self._type_ == OsvVersionRangeType.ECOSYSTEM and package and package.ecosystem:
            vers_type = package.ecosystem.value.lower()
        event_vers = '|'.join(list(map(lambda e: e.as_purl_vers_component(), self.events)))
        purl_vers = f'vers:{vers_type}/{event_vers}'
        return purl_vers


class OsvVulnerabilityId(str):
    """
    .. see:
        https://ossf.github.io/osv-schema/#id-modified-fields
    """

    _KNOWN_DATABASE_PREFIXES = ['GO', 'OSV', 'PYSEC', 'RUSTSEC', 'GSD', 'GHSA', 'LBSEC']

    def __init__(self, content: str) -> None:
        matches = re.findall(_PATTERN_VULNERABILITY_ID, content)
        if not matches:
            raise InvalidVulnerabilityIdException(f'Supplied ID for Vulnerability does not match OSV Schema: {content}')

        db_prefix, entry_id = matches[0]
        self._db_prefix: str = db_prefix.upper()
        self._entry_id: str = entry_id

    @property
    def db_prefix(self) -> str:
        """
        Identifies which database this Vulnerability originated from.

        See https://ossf.github.io/osv-schema/#id-modified-fields

        Returns:
            `str`
        """
        return self._db_prefix

    @property
    def entry_id(self) -> str:
        """
        Entry identifier within the database for this Vulnerability.

        Returns:
             `str`
        """
        return self._entry_id

    def is_from_known_database(self) -> bool:
        """
        OSSF lists a set of databases. If this identifier is from one of these, will return `True`.

        See https://ossf.github.io/osv-schema/#id-modified-fields

        Returns:
            `bool`
        """
        return self.db_prefix in self._KNOWN_DATABASE_PREFIXES

    def __eq__(self, other: object) -> bool:
        if isinstance(other, OsvVulnerabilityId):
            return hash(self) == hash(other)
        return False

    def __hash__(self) -> int:
        return hash((self.db_prefix, self.entry_id))

    def __str__(self) -> str:
        return f'{self.db_prefix}-{self._entry_id}'


class OsvAffected(JsonDeserialisable):
    """
    Describes affected package versions.

    See https://ossf.github.io/osv-schema/#affected-fields
    """

    def __init__(self, *, package: OsvPackage, ranges: Optional[List[OsvVersionRange]] = None,
                 versions: Optional[List[str]] = None) -> None:
        self._package = package
        self._ranges = ranges
        self._versions: List[str] = versions if versions else []

    @staticmethod
    def from_json(data: Dict[str, Any]) -> 'OsvAffected':
        return OsvAffected(
            package=OsvPackage(**data['package']),
            ranges=list(map(lambda r: OsvVersionRange.from_json(data=r), data['ranges'])) if 'ranges' in data else None,
            versions=data['versions'] if 'versions' in data else []
        )

    @property
    def package(self) -> OsvPackage:
        """
        Identifies the affected code library or command.

        Returns:
            `OsvPackage`
        """
        return self._package

    @property
    def ranges(self) -> Optional[List[OsvVersionRange]]:
        """
        An optional list of ranges of affected versions, under a given defined ordering.

        Returns:
            `List[OsvVersionRange]` or `None`
        """
        return self._ranges

    @property
    def versions(self) -> List[str]:
        """
        Set of strings where a string is a single affected version in whatever version syntax is used by the given
        package ecosystem.

        Returns:
             `List[str]` or `None`
        """
        return self._versions


class OsvVulnerability:
    """
    Describes a Vulnerability according to OSV schema.

    See https://ossf.github.io/osv-schema
    """

    def __init__(self, *, id_: OsvVulnerabilityId, modified: datetime, published: Optional[datetime] = None,
                 withdrawn: Optional[datetime] = None, aliases: Optional[Iterable[OsvVulnerabilityId]] = None,
                 related: Optional[Iterable[OsvVulnerabilityId]] = None, summary: Optional[str] = None,
                 details: Optional[str] = None, severity: Optional[Iterable[OsvSeverity]] = None,
                 affected: Optional[Iterable[OsvAffected]] = None, references: Optional[Iterable[OsvReference]] = None,
                 credits_: Optional[Iterable[OsvCredit]] = None,
                 schema_version: OsvSchemaVersion = DEFAULT_OSV_SCHEMA_VERSION) -> None:
        self.schema_version = schema_version
        self._id_ = id_
        self.modified = modified
        self.published = published
        self.withdrawn = withdrawn
        self.aliases = aliases or []  # type: ignore
        self.related = related or []  # type: ignore
        self.summary = summary
        self.details = details
        self.severity = severity or []  # type: ignore
        self.affected = affected or []  # type: ignore
        self.references = references or []  # type: ignore
        self.credits = credits_ or []  # type: ignore

    @staticmethod
    def from_json(data: Dict[str, Any]) -> 'OsvVulnerability':
        KEY_MAPPINGS = {'id': 'id_'}
        KEY_REMOVALS = ['database_specific']
        DATA_CLASS_MAPPINGS = {
            'id_': OsvVulnerabilityId,
            'modified': _deserialise_date,
            'published': _deserialise_date,
            'aliases': OsvVulnerabilityId,
            'related': OsvVulnerabilityId,
            'severity': OsvSeverity,
            'affected': OsvAffected,
            'references': OsvReference,
            'credits': OsvCredit,
            'schema_version': OsvSchemaVersion
        }

        v_data = copy(data)
        for k, v in data.items():
            if k in KEY_MAPPINGS:
                del (v_data[k])
                v_data[KEY_MAPPINGS[k]] = v
            if k in KEY_REMOVALS:
                del (v_data[k])

        for k, v in v_data.items():
            if k in DATA_CLASS_MAPPINGS:
                klass: Type[JsonDeserialisable] = DATA_CLASS_MAPPINGS[k]
                if isinstance(v, (list, set)):
                    items = []
                    for j in v:
                        if inspect.isclass(klass) and issubclass(klass, JsonDeserialisable):
                            items.append(klass.from_json(data=j))
                        else:
                            items.append(klass(j))
                    v_data[k] = items
                else:
                    if inspect.isclass(klass) and issubclass(klass, JsonDeserialisable):
                        v_data[k] = klass.from_json(data=v)
                    else:
                        v_data[k] = klass(v)

        return OsvVulnerability(**v_data)

    @property
    def schema_version(self) -> OsvSchemaVersion:
        """
        The schema_version field is used to indicate which version of the OSV schema a particular vulnerability was
        exported with. This can help consumer applications decide how to import the data for their own systems and
        offer some protection against future breaking changes. The value should be a string matching the OSV Schema
        version, which follows the SemVer 2.0.0 format, with no leading “v” prefix. If no value is specified, it should
        be assumed to be 1.0.0, matching version 1.0 of the OSV Schema. Clients can assume that new minor and patch
        versions of the schema only add new fields, without changing the meaning of old fields, so that a client that
        knows how to read version 1.2.0 can process data identifying as schema version 1.3.0 by ignoring any unexpected
        fields.

        Returns:
            `OsvSchemaVersion`
        """
        return self._schema_version

    @schema_version.setter
    def schema_version(self, schema_version: OsvSchemaVersion) -> None:
        self._schema_version = schema_version

    @property
    def id_(self) -> OsvVulnerabilityId:
        """
        The id field is a unique identifier for the vulnerability entry. It is a string of the format <DB>-<ENTRYID>,
        where DB names the database and ENTRYID is in the format used by the database. For example: “OSV-2020-111”,
        “CVE-2021-3114”, or “GHSA-vp9c-fpxx-744v”.

        Returns:
            `OsvVulnerabilityId`
        """
        return self._id_

    @id_.setter
    def id_(self, id_: OsvVulnerabilityId) -> None:
        self._id_ = id_

    @property
    def modified(self) -> datetime:
        """
        The modified field gives the time the entry was last modified, as an RFC3339-formatted timestamp in UTC (ending
        in “Z”). Given two different entries claiming to describe the same id field, the one with the later
        modification time is considered authoritative.

        Returns:
            `datetime`
        """
        return self._modified

    @modified.setter
    def modified(self, modified: datetime) -> None:
        self._modified = modified

    @property
    def published(self) -> Optional[datetime]:
        """
        The published field gives the time the entry should be considered to have been published, as an
        RFC3339-formatted time stamp in UTC (ending in “Z”).

        Returns:
            `datetime`
        """
        return self._published

    @published.setter
    def published(self, published: Optional[datetime]) -> None:
        self._published = published

    @property
    def withdrawn(self) -> Optional[datetime]:
        """
        The withdrawn field gives the time the entry should be considered to have been withdrawn, as an
        RFC3339-formatted timestamp in UTC (ending in “Z”). If the field is missing, then the entry has not been
        withdrawn. Any rationale for why the vulnerability has been withdrawn should go into the summary text.

        Returns:
            `datetime`
        """
        return self._withdrawn

    @withdrawn.setter
    def withdrawn(self, withdrawn: Optional[datetime]) -> None:
        self._withdrawn = withdrawn

    @property
    def aliases(self) -> Set[OsvVulnerabilityId]:
        """
        The aliases field gives a list of IDs of the same vulnerability in other databases, in the form of the id
        field. This allows one database to claim that its own entry describes the same vulnerability as one or more
        entries in other databases.

        Returns:
            `Set[OsvVulnerabilityId]`
        """
        return self._aliases

    @aliases.setter
    def aliases(self, aliases: Iterable[OsvVulnerabilityId]) -> None:
        self._aliases = set(aliases)

    @property
    def related(self) -> Set[OsvVulnerabilityId]:
        """
        The related field gives a list of IDs of closely related vulnerabilities, such as the same problem in
        alternate ecosystems.

        Returns:
            `Set[OsvVulnerabilityId]`
        """
        return self._related

    @related.setter
    def related(self, related: Iterable[OsvVulnerabilityId]) -> None:
        self._related = set(related)

    @property
    def summary(self) -> Optional[str]:
        """
        The summary field gives a one-line, English textual summary of the vulnerability. It is recommended that this
        field be kept short, on the order of no more than 120 characters.

        The summary field is plain text.

        Returns:
             `str`
        """
        return self._summary

    @summary.setter
    def summary(self, summary: Optional[str]) -> None:
        self._summary = summary

    @property
    def details(self) -> Optional[str]:
        """
        The details field gives additional English textual details about the vulnerability.

        The details field is CommonMark markdown (a subset of GitHub-Flavored Markdown). Display code may at its
        discretion sanitize the input further, such as stripping raw HTML and links that do not start with http:// or
        https://. Databases are encouraged not to include those in the first place. (The goal is to balance
        flexibility of presentation with not exposing vulnerability database display sites to unnecessary
        vulnerabilities.)

        Returns:
            `str` or `None`
        """
        return self._details

    @details.setter
    def details(self, details: Optional[str]) -> None:
        self._details = details

    @property
    def severity(self) -> Set[OsvSeverity]:
        """
        An array that allows generating systems to describe the severity of a vulnerability using one or more
        quantitative scoring methods.

        Returns:
            `Set[OsvSeverity]`
        """
        return self._severity

    @severity.setter
    def severity(self, severity: Iterable[OsvSeverity]) -> None:
        self._severity = set(severity)

    @property
    def affected(self) -> Set[OsvAffected]:
        """
        Set that describes the affected package versions, meaning those that contain the vulnerability.

        Returns:
            `Set[OsvAffected]`
        """
        return self._affected

    @affected.setter
    def affected(self, affected: Iterable[OsvAffected]) -> None:
        self._affected = set(affected)

    @property
    def references(self) -> Set[OsvReference]:
        """
        A set of references.

        Returns:
            `Set[OsvReference]`
        """
        return self._references

    @references.setter
    def references(self, references: Iterable[OsvReference]) -> None:
        self._references = set(references)

    @property
    def credits(self) -> Set[OsvCredit]:
        """
        Set of individuals or entities being credited with discovering this Vulnerability.

        Returns:
            `Set[OsvCredit]`
        """
        return self._credits

    @credits.setter
    def credits(self, credits_: Iterable[OsvCredit]) -> None:
        self._credits = set(credits_)
