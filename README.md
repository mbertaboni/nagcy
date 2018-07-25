# nagcy
Nagios Cylance Checker

Just a test of the Cylance API with a reckless use of Python.
Sorry Python-lovers, it's my first attempt..

## Disclaimer
This software is **NOT** provided or written by Cylance.
I'm not from Cylance, this code is **NOT** validated or approved by Cylance.

## What you can do
What you can do with this script, connected to nagios

- Check in your Venue console if the device is safe or not
- Check in your Venue console the state of the device (Online/Offline)
- Check in your Venue console if the device is offline for more than X days

## Requirements:

jwt, requests, python 2.7

## Limitations:

- A lot, no proxy support, no support for duplicated device as we use the ip address as primary connection between nagios and Venue.
- Probably a plenty of bugs

## Setup:
Open the file and insert
- Venue Tenant ID
- Venue App ID
- Venue App Secret
- Your Tenant's Region
