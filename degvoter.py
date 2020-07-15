#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" degvoter that doesn't suck [so much]

    The proper PoC implementation of a garbage voter national ID verification
    tool discovered and documented by Meduza.io [1]. The implementation is
    based on ideas layed out in [2] Twitter thread as well as suggested by
    Evgeny Fedin [3]. It is a personal project made for fun in a few spare
    hours, tune your expectations accordingly.

    Unlike the original implementation (by the DIT of Moscow) which stored
    passport ID hashes in a SQL database, we are employing two Bloom filters:
        Voters (regular, high false positives rate)
        NonVoters (counting, low false positives rate)
    Both filters are initialized up to the total number of voters eligible
    for the e-voting. When a voter registers for the e-voting, their passport
    ID hash is stored into the NonVoters filter; then, once an electronic
    ballot is casted, the passport ID hash is removed from the NonVoters
    filter and added to the Voters filter. (At the end of the e-voting period
    the union of both filters should represent a cohort of all the voters
    registered for the e-voting, regardless of whether they participated in
    the procedure or not.)

    To determine whether a voter is eligible for a traditional paper ballot
    voting (i.e. if he/she opted out of e-voting by not casting an electronic
    ballot after registering), the following steps are performed:
        Check Voters filter for a passport ID.
            If match (probabilistic) check NonVoters filter for a passport ID.
                If match (probabilistic) -> voter is eligible.
                Else (deterministic) -> voter is ineligible.
            Else (deterministic) -> voter is eligible.
    This ensures the following requirements are met:
        An eligible voter must not be refused to vote;
        An ineligible voter may have a low chance for a double vote.
    The latter is deemed acceptable since a voter cannot know in advance their
    passport ID check would match false positive, and the chance is
    configurable with the NonVoters filter false positives rate.

    In order to protect against brute force hash preimage attacks to recover
    all passport IDs (the bane of the original degvoter implementation which
    lacked any protection due to plain hashing of ID values), Argon2 KDF along
    with a salt is used to slow down verification attempts. However instead of
    a random unique salt value per passport ID, the current PoC follows a non-
    standard approach: a passport issue date is used for the salt value
    instead. A rationale for this is the following. Although there are certain
    biases, it is presumed the passport numbers are distributed evenly enough
    over the issue date range; passport numbers are not directly correlated
    with issue dates since numbers are a simple cyclic counter [4]. According
    to the analysis [1] of the leaked database, there were at most 100k
    passports issued in any year, or roughly 275 (2^8.1) per day on average.
    The practical entropy of an issue date is less than anticipated since the
    year of a passport issue can be deduced with certain precision (roughly
    +/- 3 years [4]) from the ID (its serial number part); this leaves us with
    slightly over 2^8.5 bits of entropy which is on par with the max number of
    IDs issued in a day, hence deemed enough (albeit at the lower boundary)
    for protection against exhaustive search attacks.

    [1] https://meduza.io/feature/2020/07/09/vlasti-fakticheski-vylozhili-v-otkrytyy-dostup-personalnye-dannye-vseh-internet-izbirateley
    [2] https://twitter.com/__sattva/status/1281655790944899072
    [3] https://twitter.com/efedin_ru/status/1281667607373000706
    [4] https://habr.com/ru/company/hflabs/blog/478538/



    Copyright (c) 2020, Vlad Miller, All rights reserved.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of the <ORGANIZATION> nor the names of its
      contributors may be used to endorse or promote products derived from
      this software without specific prior written permission.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
    IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
    THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
    PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
    CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
    EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
    PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
    OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
    LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
    NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
    SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""

import argon2
import argparse
import os.path
import pickle
import re
import sys
import time
import typing
from probables import BloomFilter, CountingBloomFilter


# Computation complexity (resource cost) settings for Argon2 key derivation
# function. The following configuration is tuned for roughly 0.5 sec/op on a
# decently modern hardware.
KDF_PARAMETERS = {
    'time_cost': 1,
    'memory_cost': 1024 * 1024,  # 1 GB.
    'parallelism': 8,
    'hash_len': 8,  # 64 bits (Bloom filter hash size limit).
}

# Bloom filter settings for Voters and NonVoters sets (see module documentation
# for details).
FILTER_PARAMETERS = {
    'voters': {'type': BloomFilter, 'false_positive_rate': 0.1},
    'non_voters': {'type': CountingBloomFilter, 'false_positive_rate': 0.001}
}

# Filename mask for exported Bloom filter files.
FILTERS_FILENAME = 'degvoter_{}.blf'
# Filename serialized KDF parameters.
KDFS_FILENAME = 'degvoter_kdfs.pkl'


class PassportID(object):
    """Passport ID struct. Expects the following format (being liberal on
    date segment separators): ['SSSS', 'NNNNNN', 'DD.MM.YYYY']. Raises
    ValueError if the format is not met. Date is not checked for correctness."""

    id: str = None  # Ex. "0099123456"
    issued: str = None  # Ex. "01072008"
    _mask = re.compile('^(\\d{4})\\s+(\\d{6})\\s+(\\d{2}\\D\\d{2}\\D\\d{4})$')
    _nondigits = re.compile('\\D')

    def __init__(self, passport_id: list):
        matches = self._mask.findall(' '.join(passport_id).strip())

        if matches:
            self.id = ''.join(matches[0][:2])
            self.issued = self._nondigits.sub('', matches[0][2])
        else:
            raise ValueError('Invalid passport ID format')

    def __repr__(self):
        return '<{} {}>'.format(self.id, self.issued)


class KDF(object):
    """ Configurable pyprobables-compatible wrapper over Argon2 KDF.

        We need it to be able to store KDF complexity parameters depending on
        the hashing strategy for selected Bloom filter probability settings.

        Initialization takes Bloom filter constructor arguments, calculates
        the required hash depth for the given filter and uses it to adjust
        KDF output length (e.g. for a hash depth = 3 we are going to use
        8 * 3 = 24 bytes output). The increased hash output is in turn split
        in equal parts of the original size, the produced list of values is
        used as a Bloom filter entry. This approach guarantees the Argon2
        security properties are not degraded.
    """

    parameters: dict = None
    hash_depth: int = None
    _salt_len = 8

    def __init__(self, est_elements: int, false_positive_rate: float):
        _, _, self.hash_depth, _ = BloomFilter._set_optimized_params(
                est_elements, false_positive_rate, None)
        self.parameters = KDF_PARAMETERS.copy()
        self.parameters['hash_len'] *= self.hash_depth

    def __call__(self, key: PassportID, depth: int = 1) -> list:
        """Hash the passport ID, return a list of hash integers for the Bloom
        filter entry."""
        kdf_tag = self._hash(data=key.id.encode('utf-8'),
                             salt=key.issued.encode('utf-8'))
        chunk_len = self.parameters['hash_len'] // self.hash_depth
        return [int.from_bytes(bytearray(item), 'big')
                for item in zip(*[iter(kdf_tag)] * chunk_len)]

    def _hash(self, data: bytes, salt: bytes) -> bytes:
        return argon2.low_level.hash_secret_raw(
                data, salt.rjust(self._salt_len, b'0'),
                type=argon2.low_level.Type.ID, **self.parameters)


class Filters(object):
    """Bloom filters management harness."""

    filters: dict = None
    kdfs: dict = None

    def __init__(self):
        self.filters = {}
        self.kdfs = {}

    def __repr__(self):
        return repr(self.filters)

    def init(self, est_elements: int):
        """Create new empty filters for storing the estimated number of
        elements."""
        for name, params in FILTER_PARAMETERS.items():
            filter_cls = params['type']
            false_positive_rate = params['false_positive_rate']
            kwargs = {'est_elements': est_elements,
                      'false_positive_rate': false_positive_rate}
            hash_function = KDF(**kwargs)
            bloom = filter_cls(hash_function=hash_function, **kwargs)
            self.filters[name] = bloom
            self.kdfs[name] = hash_function

    def dump(self) -> typing.Generator[str, None, None]:
        """Export Bloom filters and KDF parameters to disk yielding created
        file names (relative to the script file name)."""
        for name in FILTER_PARAMETERS:
            bloom = self.filters[name]
            filename = FILTERS_FILENAME.format(name)
            bloom.export(abs_path(filename))
            yield filename

        with open(abs_path(KDFS_FILENAME), 'wb') as file:
            pickle.dump(self.kdfs, file)
        yield KDFS_FILENAME

    def load(self) -> typing.Generator[str, None, None]:
        """Import Bloom filters and KDF parameters from disk, yielding loaded
        file names prior to the load operation and populating the 'filters',
        'kdfs' attributes after."""
        with open(abs_path(KDFS_FILENAME), 'rb') as file:
            self.kdfs = pickle.load(file)
        yield KDFS_FILENAME

        for name, params in FILTER_PARAMETERS.items():
            filter_cls = params['type']
            filename = FILTERS_FILENAME.format(name)
            yield filename
            bloom = filter_cls(filepath=abs_path(filename),
                               hash_function=self.kdfs[name])
            self.filters[name] = bloom

    @property
    def voters(self):
        """Voters Bloom filter."""
        return self.filters['voters']

    @property
    def non_voters(self):
        """NonVoters Bloom filter."""
        return self.filters['non_voters']


class Action(object):
    """Actions dispatcher. Action methods does not return but emit a system
    status code instead (implicitly 0; explicitly 1 no error results, 2 on
    usage errors)."""

    args: argparse.Namespace = None
    action: str = None
    filters: Filters = None
    _t1: float = None

    def __init__(self, args: argparse.Namespace):
        self._t1 = time.monotonic()
        self.args = args
        self.action = args.action

    def __call__(self):
        method = getattr(self, self.action)
        return method()

    def _info(self, message, *args):
        elapsed = time.monotonic() - self._t1
        print('{:>7}:  {}'.format(round(elapsed, 3), message.format(*args)))

    def _error(self, message):
        self._info('ERROR: ' + message)

    def _load_filters(self):
        self._info('Loading Bloom filters:')
        self.filters = Filters()
        try:
            for filename in self.filters.load():
                self._info('    ' + filename)
        except OSError:
            self._error('Filters not found, run "init" action first')
            sys.exit(2)

    def _dump_filters(self):
        self._info('Saving Bloom filters:')
        for filename in self.filters.dump():
            self._info('    ' + filename)

    def init(self):
        size = self.args.voters
        self._info('Initializing Bloom filters for {} voters', size)
        self.filters = Filters()
        self.filters.init(size)
        self._dump_filters()

    def reg(self):
        # We are not checking whether a voter has already registered before,
        # it doesn't matter since we'll simply reset the counter while casting
        # an e-ballot.
        self._load_filters()
        self._info('Registering voter: {}', self.args.passport)
        self.filters.non_voters.add(self.args.passport)
        self._dump_filters()

    def vote(self):
        self._load_filters()
        self._info('Voter casts an e-voting ballot: {}', self.args.passport)
        result = self.filters.non_voters.check(self.args.passport)

        if result:
            self.filters.non_voters.remove(self.args.passport, num_els=result)
            self.filters.voters.add(self.args.passport)
            self._info('Voter marked as casted an e-ballot')
            self._dump_filters()
        else:
            self._error('Voter is either not registered or has already voted')
            sys.exit(1)

    def check(self):
        self._load_filters()
        self._info('Checking voter for paper ballot eligibility: {}',
                   self.args.passport)

        if self.filters.voters.check(self.args.passport):
            eligible = self.filters.non_voters.check(self.args.passport)
        else:
            eligible = True

        if eligible:
            self._info('Voter is eligible')
        else:
            self._error('Voter has already voted')
            sys.exit(1)


def abs_path(pathname: str) -> str:
    """Transform a script-relative path to an absolute path."""
    directory = os.path.dirname(os.path.abspath(__file__))
    return os.path.normpath(os.path.join(directory, pathname))


def parse_args() -> argparse.Namespace:
    epilog = '''notes:
    Passport IDs must be specified in the following format:
    <series SSSS> <number NNNNNN> <issue date DD.MM.YYYY>

examples:
    Initialize database for 1M voters:
    {name} init 1000000

    Register passport ID for e-voting:
    {name} reg 0099 123456 01.07.2008

    Mark passport ID as casted e-voting ballot:
    {name} vote 0099 123456 01.07.2008

    Check passport ID for paper voting eligibility:
    {name} check 0099 123456 01.07.2008'''.format(name=sys.argv[0])

    # noinspection PyTypeChecker
    parser = argparse.ArgumentParser(
            description='degvoter that doesn\'t suck [so much]. See module '
                        'docstrings for rationale and implementation details.',
            epilog=epilog, formatter_class=argparse.RawDescriptionHelpFormatter)
    subparsers = parser.add_subparsers(
            dest='action', description='(Call "<subcommand> -h" for details)')

    init_parser = subparsers.add_parser('init', help='Initialize voters DB')
    init_parser.add_argument('voters', type=int,
                             help='Number of eligible voters')

    passport_parser = argparse.ArgumentParser(add_help=False)
    passport_parser.add_argument('passport', nargs=argparse.REMAINDER,
                                 help='Passport ID as <series SSSS> '
                                      '<number NNNNNN> <issue date DD.MM.YYYY>')

    subparsers.add_parser('reg', parents=[passport_parser],
                          help='Register for e-voting')
    subparsers.add_parser('vote', parents=[passport_parser],
                          help='Mark as casted e-ballot')
    subparsers.add_parser('check', parents=[passport_parser],
                          help='Check for paper voting eligibility')

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()

    if hasattr(args, 'passport'):
        try:
            # noinspection PyTypeChecker
            args.passport = PassportID(args.passport)
        except ValueError as exc:
            parser.error(str(exc))

    return args


def main():
    args = parse_args()
    action = Action(args)
    action()


if __name__ == '__main__':
    main()
