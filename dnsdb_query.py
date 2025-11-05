#!/usr/bin/env python

# Copyright (c) 2013 by Farsight Security, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import calendar
import errno
import locale
import argparse
import os
import sys
import time
import urllib.request, urllib.error, urllib.parse
from io import StringIO


try:
    import json
except ImportError:
    import simplejson as json

DEFAULT_CONFIG_FILE = '/etc/dnsdb-query.conf'
DEFAULT_DNSDB_SERVER = 'https://api.dnsdb.info'

cfg = None
options = None

locale.setlocale(locale.LC_ALL, '')

class DnsdbClient(object):
    def __init__(self, server, apikey, limit=None):
        self.server = server
        self.apikey = apikey
        self.limit = limit

    def query_rrset(self, oname, rrtype=None, bailiwick=None):
        if bailiwick:
            if not rrtype:
                rrtype = 'ANY'
            path = 'rrset/name/%s/%s/%s' % (oname, rrtype, bailiwick)
        elif rrtype:
            path = 'rrset/name/%s/%s' % (oname, rrtype)
        else:
            path = 'rrset/name/%s' % oname
        return self._query(path)

    def query_rdata_name(self, rdata_name, rrtype=None):
        if rrtype:
            path = 'rdata/name/%s/%s' % (rdata_name, rrtype)
        else:
            path = 'rdata/name/%s' % rdata_name
        return self._query(path)

    def query_rdata_ip(self, rdata_ip):
        path = 'rdata/ip/%s' % rdata_ip.replace('/', ',')
        return self._query(path)

    def _query(self, path):
        res = []
        url = '%s/lookup/%s' % (self.server, path)
        if self.limit:
            url += '?limit=%d' % self.limit
        req = urllib.request.Request(url)
        req.add_header('Accept', 'application/json')
        req.add_header('X-Api-Key', self.apikey)
        try:
            http = urllib.request.urlopen(req)
            while True:
                line = http.readline()
                if not line:
                    break
                res.append(json.loads(line))
        except (urllib.error.HTTPError, urllib.error.URLError) as e:
            sys.stderr.write(str(e) + '\n')
        return res

def sec_to_text(ts):
    return time.strftime('%Y-%m-%d %H:%M:%S -0000', time.gmtime(ts))

def rrset_to_text(m):
    s = StringIO()

    if 'bailiwick' in m:
        s.write(';;  bailiwick: %s\n' % m['bailiwick'])

    if 'count' in m:
        s.write(';;      count: %s\n' % locale.format_string('%d', m['count'], True))

    if 'time_first' in m:
        s.write(';; first seen: %s\n' % sec_to_text(m['time_first']))
    if 'time_last' in m:
        s.write(';;  last seen: %s\n' % sec_to_text(m['time_last']))

    if 'zone_time_first' in m:
        s.write(';; first seen in zone file: %s\n' % sec_to_text(m['zone_time_first']))
    if 'zone_time_last' in m:
        s.write(';;  last seen in zone file: %s\n' % sec_to_text(m['zone_time_last']))

    if 'rdata' in m:
        for rdata in m['rdata']:
            s.write('%s IN %s %s\n' % (m['rrname'], m['rrtype'], rdata))

    s.seek(0)
    return s.read()

def rdata_to_text(m):
    return '%s IN %s %s' % (m['rrname'], m['rrtype'], m['rdata'])

def parse_config(cfg_fname):
    config = {}
    cfg_files = list(filter(os.path.isfile,
            (cfg_fname, os.path.expanduser('~/.dnsdb-query.conf'))))

    if not cfg_files:
        raise IOError(errno.ENOENT, 'dnsdb_query: No config files found')

    for fname in cfg_files:
        for line in open(fname):
            key, eq, val = line.strip().partition('=')
            val = val.strip('"')
            config[key] = val

    return config

def time_parse(s):
    try:
        epoch = int(s)
        return epoch
    except ValueError:
        pass

    try:
        epoch = int(calendar.timegm(time.strptime(s, '%Y-%m-%d')))
        return epoch
    except ValueError:
        pass

    try:
        epoch = int(calendar.timegm(time.strptime(s, '%Y-%m-%d %H:%M:%S')))
        return epoch
    except ValueError:
        pass

    raise ValueError('Invalid time: "%s"' % s)

def filter_before(res_list, before_time):
    before_time = time_parse(before_time)
    new_res_list = []

    for res in res_list:
        if 'time_first' in res:
            if res['time_first'] < before_time:
                new_res_list.append(res)
        elif 'zone_time_first' in res:
            if res['zone_time_first'] < before_time:
                new_res_list.append(res)
        else:
            new_res_list.append(res)

    return new_res_list

def filter_after(res_list, after_time):
    after_time = time_parse(after_time)
    new_res_list = []

    for res in res_list:
        if 'time_last' in res:
            if res['time_last'] > after_time:
                new_res_list.append(res)
        elif 'zone_time_last' in res:
            if res['zone_time_last'] > after_time:
                new_res_list.append(res)
        else:
            new_res_list.append(res)

    return new_res_list

def main():
    global cfg
    global options

    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--config', dest='config', type='str',
        help='config file', default=DEFAULT_CONFIG_FILE)
    parser.add_argument('-r', '--rrset', dest='rrset', type='str',
        help='rrset <ONAME>[/<RRTYPE>[/BAILIWICK]]')
    parser.add_argument('-n', '--rdataname', dest='rdata_name', type='str',
        help='rdata name <NAME>[/<RRTYPE>]')
    parser.add_argument('-i', '--rdataip', dest='rdata_ip', type='str',
        help='rdata ip <IPADDRESS|IPRANGE|IPNETWORK>')
    parser.add_argument('-s', '--sort', dest='sort', type='str', help='sort key')
    parser.add_argument('-R', '--reverse', dest='reverse', action='store_true', default=False,
        help='reverse sort')
    parser.add_argument('-j', '--json', dest='json', action='store_true', default=False,
        help='output in JSON format')
    parser.add_argument('-l', '--limit', dest='limit', type='int', default=0,
        help='limit number of results')

    parser.add_argument('', '--before', dest='before', type='str', help='only output results seen before this time')
    parser.add_argument('', '--after', dest='after', type='str', help='only output results seen after this time')

    args = parser.parse_args()
    if args:
        parser.print_help()
        sys.exit(1)

    try:
        cfg = parse_config(args.config)
    except IOError as e:
        sys.stderr.write(str(e))
        sys.exit(1)


    if not 'DNSDB_SERVER' in cfg:
        cfg['DNSDB_SERVER'] = DEFAULT_DNSDB_SERVER
    if not 'APIKEY' in cfg:
        sys.stderr.write('dnsdb_query: APIKEY not defined in config file\n')
        sys.exit(1)

    client = DnsdbClient(cfg['DNSDB_SERVER'], cfg['APIKEY'], args.limit)
    if args.rrset:
        res_list = client.query_rrset(*args.rrset.split('/'))
        fmt_func = rrset_to_text
    elif args.rdata_name:
        res_list = client.query_rdata_name(*args.rdata_name.split('/'))
        fmt_func = rdata_to_text
    elif args.rdata_ip:
        res_list = client.query_rdata_ip(args.rdata_ip)
        fmt_func = rdata_to_text
    else:
        parser.print_help()
        sys.exit(1)

    if args.json:
        fmt_func = json.dumps

    if len(res_list) > 0:
        if args.sort:
            if not args.sort in res_list[0]:
                sort_keys = list(res_list[0].keys())
                sort_keys.sort()
                sys.stderr.write('dnsdb_query: invalid sort key "%s". valid sort keys are %s\n' % (args.sort, ', '.join(sort_keys)))
                sys.exit(1)
            res_list.sort(key=lambda r: r[args.sort], reverse=args.reverse)
        if args.before:
            res_list = filter_before(res_list, args.before)
        if args.after:
            res_list = filter_after(res_list, args.after)

    for res in res_list:
        sys.stdout.write('%s\n' % fmt_func(res))

if __name__ == '__main__':
    main()
