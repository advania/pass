#!/usr/bin/env python3

# Example script using the json api to create a link and then email it using
# the provided API

import requests
import json
import argparse
import sys

parser = argparse.ArgumentParser()
parser.add_argument('endpoint')
parser.add_argument('recipient')
parser.add_argument('secret')

args = parser.parse_args()

url = args.endpoint

####

r = requests.Session()

r.headers = {
    'Accept': 'application/json',
}

def send(r, url, data):
    result = r.post(url, data=data)

    if result.status_code != 200:
        print(result.text)
        sys.exit(1)

    result = result.json()

    print(json.dumps(result, indent=4))

    return result


print('Sending link creation request')

step1 = send(r, url, { 'secret': args.secret })

####

print('----\nSending email delivery request')

step2 = send(r, '{}/{}/email'.format(url, step1['uuid']), { 'email': args.recipient })
