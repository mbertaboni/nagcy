#!/usr/bin/env python
#
# nagcy - Nagios Cylance Checker - https://github.com/mbertaboni/nagcy
# Copyright (C) 2018 Maurizio Bertaboni
# LOOK DOWN for SETUP !
# Nagios Cylance Checker (this file) is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# any later version.
#
# Nagios Cylance Checker (this file) is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# If not, see <http://www.gnu.org/licenses/>.
#
import jwt  # PyJWT version 1.5.3 as of the time of authoring.
import uuid
import requests  # requests version 2.18.4 as of the time of authoring.
import json
import sys
import argparse
import collections
import urllib2
import socket
from datetime import datetime, timedelta
from dateutil import tz
# **********************************  SETUP
# The tenant's unique identifier.
tid_val = ""
# The application's unique identifier.
app_id = ""
# The application's secret to sign the auth token with.
app_secret = ""
# choose your region (us for USgov, -euc1 for EMEA, let empty for North America)
prefix = "-euc1"
# ********************************** END SETUP

if tid_val == "" or app_id == "" or app_secret == "":
    print "ERROR - you must configure NagCy in order to run..."
    sys.exit(0)

AUTH_URL = "https://protectapi" + prefix + ".cylance.com/auth/v2/token"

# I know, from now on is all horrible..but seems to work


def build_url(object_type, page_number, page_size, unique_id="?"):
    if unique_id != '?':
        the_url = "https://protectapi" + prefix + ".cylance.com/" + object_type + \
            "/v2/" + unique_id
    else:
        the_url = "https://protectapi" + prefix + ".cylance.com/" + object_type + \
            "/v2/" + unique_id + "page=" + str(page_number) + \
            "&page_size=" + str(page_size)
    return the_url


def usage():
    print('Usage: Choose the type of the check and pass the HOSTADDRESS as argument, try with --help')


def parse_args(argv):
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-s", metavar='HOSTADDRESS', nargs=1,
                       help='Check if device is safe')
    group.add_argument("-o", metavar='HOSTADDRESS', nargs=1,
                       help='Check if device is offline')
    group.add_argument("-t", metavar=('HOSTADDRESS', 'NUMBER_OF_DAYS'),
                       nargs=2, help='Check if a device is offline for more than')
    args = parser.parse_args(argv)
    return args


def check_safe_device(ip):
    try:
        socket.inet_aton(str(ip))
        device_id = get_devid_from_ip(ip)
        if device_id:
            details = get_device_detail(device_id)
            if details['is_safe'] == True:
                print "OK - " + details['name'] + " is safe"
                sys.exit(0)
            else:
                print "CRITICAL - " + details['name'] + " is NOT safe"
                sys.exit(2)
        else:
            print "UNKNOWN - not found"
            sys.exit(3)
    except socket.error:
        print "not a valid ip"


def check_offline_device(ip):
    try:
        socket.inet_aton(str(ip))
        device_id = get_devid_from_ip(ip)
        if device_id:
            details = get_device_detail(device_id)
            if details['state'] == "Online":
                print "OK - " + details['name'] + " is online"
                sys.exit(0)
            else:
                print "CRITICAL - " + details['name'] + " is offline"
                sys.exit(2)
        else:
            print "UNKNOWN - not found"
            sys.exit(3)
    except socket.error:
        print "not a valid ip"


def check_offline_time(ip, days_to_subtract):
    try:
        socket.inet_aton(str(ip))
        device_id = get_devid_from_ip(ip)
        if device_id:
            details = get_device_detail(device_id)
            days_to_subtract = int(days_to_subtract)
            offline_date = details['date_offline']
            utc = tz.tzutc()
            local_zone = tz.tzlocal()
            offline_utc = datetime.strptime(
                offline_date, '%Y-%m-%dT%H:%M:%S.%f')
            offline_utc = offline_utc.replace(tzinfo=utc)
            offline_zone = offline_utc.astimezone(local_zone)
            offline_zone = offline_zone.replace(tzinfo=None)
            d = datetime.today() - timedelta(days=days_to_subtract)
            if offline_zone < d:
                print "CRITICAL - " + \
                    details['name'] + " is offline for more than " + \
                    str(days_to_subtract) + " days"
                sys.exit(2)
            elif offline_zone == d:
                print "WARNING - " + details['name'] + " is offline"
                sys.exit(1)
            elif offline_zone > d:
                print "OK - " + details['name'] + " is not offline for more than " + \
                    str(days_to_subtract) + " days"
                sys.exit(0)
        else:
            print "UNKNOWN - not found"
            sys.exit(3)
    except socket.error:
        print "not a valid ip"


def get_devid_from_ip(searched_ip):
    compute_request = requests.get(
        build_url('devices', 1, 200), headers=headers_request)
    number_elements = json.loads(compute_request.text)
    total_pages = int(number_elements['total_pages'])
    page = 0
    for page in str(total_pages):
        devices = requests.get(build_url('devices', int(page), 200),
                               headers=headers_request)
        devices = json.loads(devices.text)
        for device in devices['page_items']:
            for ip in device['ip_addresses']:
                if ip == searched_ip:
                    return device['id']


def get_device_detail(devid):
    detail_request = requests.get(
        build_url('devices', 1, 200, devid), headers=headers_request)
    details = json.loads(detail_request.text)
    return details


def get_token():
    timeout = 1800
    now = datetime.utcnow()
    timeout_datetime = now + timedelta(seconds=timeout)
    epoch_time = int((now - datetime(1970, 1, 1)).total_seconds())
    epoch_timeout = int(
        (timeout_datetime - datetime(1970, 1, 1)).total_seconds())
    jti_val = str(uuid.uuid4())
    claims = {
        "exp": epoch_timeout,
        "iat": epoch_time,
        "iss": "http://cylance.com",
        "sub": app_id,
        "tid": tid_val,
        "jti": jti_val
    }
    encoded = jwt.encode(claims, app_secret, algorithm='HS256')
    payload = {"auth_token": encoded}
    headers = {"Content-Type": "application/json; charset=utf-8"}
    resp = requests.post(AUTH_URL, headers=headers, data=json.dumps(payload))
    access_token = json.loads(resp.text)['access_token']
    global headers_request
    headers_request = {"Accept": "application/json",
                       "Authorization": "Bearer " + access_token,
                       "Content-Type": "application/json"}
    return access_token


if __name__ == "__main__":
    access_token = get_token()
    args = parse_args(sys.argv[1:])
    if args.s:
        check_safe_device(args.s[0])
    elif args.o:
        check_offline_device(args.o[0])
    elif args.t:
        check_offline_time(args.t[0], args.t[1])
    else:
        usage()
