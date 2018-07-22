#!/usr/bin/env python27

from __future__ import print_function

import base64
import json
import os
import sys

import boto3
from botocore.exceptions import *

OK = 0
ERROR = -1
INVALID_ARGS = -2
profile_key = 'AWS_PROFILE'
cmk = 'alias/RedshiftUtilsLambdaRunner'


def encrypt_password(args):
    if len(args) < 2:
        print("You must supply the password to be encrypted")
        sys.exit(INVALID_ARGS)
   
    try: 
        current_profile = os.environ[profile_key]
    except KeyError:
        current_profile = None

    if current_profile is None or current_profile == '':
        current_profile = 'default'

    try:
        encrypt(current_profile, args[1], None if len(args) == 2 else args[2])
        sys.exit(OK)
    except Exception as e:
        print(e)
        return ERROR


def encrypt(aws_profile, password, auth_context):
    # create a KMS connection
    session = boto3.session.Session(profile_name=aws_profile)
    kms_connection = session.client('kms')

    # check to see if the application Customer Master Key exists
    cmk_status = None
    try:
        cmk_status = kms_connection.describe_key(KeyId=cmk)
    except ClientError as e:
        if 'NotFoundException' in str(e):
            pass
        else:
            raise e

    if cmk_status is None or cmk_status['KeyMetadata'] is None:
        # create the key and an alias
        new_cmk = kms_connection.create_key(Description='AWSLambdaRedshiftUtilsPasswordEncryption',
                                            KeyUsage='ENCRYPT_DECRYPT')
        if new_cmk is None:
            print("Failed to create Customer Master Key")
            sys.exit(ERROR)
        alias = kms_connection.create_alias(AliasName=cmk,
                                            TargetKeyId=new_cmk['KeyMetadata']['KeyId'])
        print("Created new KMS Key with alias %s" % alias)

    # encrypt the provided password with this kms key
    # get the application authorisation context
    json_auth_context = None
    if auth_context is not None:
        try:
            json_auth_context = json.loads(auth_context)
        except ValueError as e:
            raise Exception("Error while encoding Auth Context to JSON: %s" % e)

    if json_auth_context is not None:
        encrypted = kms_connection.encrypt(KeyId=cmk,
                                           Plaintext=password,
                                           EncryptionContext=json_auth_context)
    else:
        encrypted = kms_connection.encrypt(KeyId=cmk,
                                           Plaintext=password)

    print("Encryption Complete with %s" % aws_profile)
    print("Encrypted Password: %s" % base64.b64encode(encrypted['CiphertextBlob']))


if __name__ == "__main__":
    encrypt_password(sys.argv)
