#!/usr/bin/env python2
""" qyery encryptonator api """
import os
import requests
import argparse
from requests.auth import HTTPBasicAuth
from requests.packages.urllib3.exceptions import InsecureRequestWarning

err_msg = """To avoid showing the password in the process list
you need to run the script in one of the following ways:
# PASSWORD='<your-password>' encryptonate_api.py -u USER -d YYYYMMDD -t TEAM"
or:
# echo "export PASSWORD='<you-password>' > ./mysecret"
# source ./mysecret &&  encryptonate_api.py -u USER -d YYYYMMDD -t TEAM
"""


def parse():
    """ parse script options """
    parser = argparse.ArgumentParser(description="query encryptonator api")
    parser.add_argument('-u', '--user', help='username', required=True)
    parser.add_argument('-d', '--directory', help='directory to list: YYYYMMDD', required=True)
    parser.add_argument('-p', '--platform', help='platform name', required=True)

    return parser.parse_args()


if __name__ == "__main__":

    ARGS = parse()
    url = 'https://encryptonator.ecg.so/{}/api'.format(ARGS.platform)
    data = dict(my_path=ARGS.directory, my_team=ARGS.platform)

    try:
        PASSWORD = os.environ['PASSWORD']
    except KeyError, err:
        print err_msg
        os.sys.exit(1)

    # disabling HTTPS Warning:
    # http://stackoverflow.com/questions/27981545/suppress-insecurerequestwarning-unverified-https-request-is-being-made-in-pytho
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    req = requests.post(url, data=data, verify=False,
                        auth=HTTPBasicAuth(ARGS.user, PASSWORD))

    print req.content
