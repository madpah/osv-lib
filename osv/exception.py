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


class OsvException(Exception):
    """
    Base exception which all exceptions raised by this library extend.
    """
    pass


class InvalidAffectedRangeException(OsvException):
    """
    Raised if the supplied data when parsing an Affected Range is not valid.
    """
    pass


class InvalidDateException(OsvException):
    """
    Raised if we try to deserialise a date in an unexpected format.
    """
    pass


class InvalidQueryParametersException(OsvException):
    """
    Raised if an invalid set of parameters are provided to a Query operation against OSV.
    """
    pass


class InvalidVersionRangeEventException(OsvException):
    """
    Raised if a Version Range Event has more than one event defined.
    """
    pass


class InvalidVulnerabilityIdException(OsvException):
    """
    Raised if a supplied ID for a Vulnerability is not valid according to the OSV Schema.
    """
    pass


class OsvApiErrorResponseException(OsvException):
    """
    Raised if OSV API returns an error.
    """
    pass
