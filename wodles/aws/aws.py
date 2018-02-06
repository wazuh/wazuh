#!/usr/bin/env python
#
# Import AWS CloudTrail
#
# Author: Wazuh, Inc.
# Copyright: GPLv3
#
#

import os
import re
import signal
import sys
import sqlite3
import argparse
from socket import socket, AF_UNIX, SOCK_DGRAM
try:
    import boto3
except ImportError:
    print('Error: No module found boto3.')
    sys.exit(4)
import botocore
import gzip
import json

# Enable/disable debug mode
enable_debug = False
# Wazuh installation path
wazuh_path = open('/etc/ossec-init.conf').readline().split('"')[1]
# Wazuh queue
wazuh_queue = '{0}/queue/ossec/queue'.format(wazuh_path)
# Wazuh tmp folder
wazuh_tmp = '{0}/tmp'.format(wazuh_path)
# Wazuh wodle path
wazuh_wodle = '{0}/wodles/aws'.format(wazuh_path)

def send_msg(wazuh_queue, header, msg):
    formatted = {}
    formatted['integration'] = 'aws'
    formatted['aws'] = msg
    debug(json.dumps(formatted, indent=4))
    formatted = '{0}{1}'.format(header, json.dumps(formatted))
    s = socket(AF_UNIX, SOCK_DGRAM)
    try:
        s.connect(wazuh_queue)
    except:
        print('Error: Wazuh must be running.')
        sys.exit(1)
    s.send(formatted.encode())
    s.close()

def handler(signal, frame):
    print "SIGINT received, bye!"
    sys.exit(1)

def already_processed(downloaded_file, db_connector):
    if db_connector:
        cursor = db_connector.execute('select count(*) from log_progress where log_name="{log_name}"'.format(log_name=downloaded_file))
        if cursor.fetchall()[0][0]:
            return True
    return False

def mark_complete(downloaded_file, db_connector):
    if db_connector:
        db_connector.execute("insert into log_progress (log_name, processed_date) values ('{log_name}', DATE('now'))".format(log_name=downloaded_file))
        db_connector.commit()

def debug(msg):
    if enable_debug:
        print(msg)

def main(argv):
    # Message header
    header = '1:Wazuh-AWS:'

    # Parse arguments
    parser = argparse.ArgumentParser(usage="usage: %prog [options]", version="%prog 1.0")
    parser.add_argument('-b', '--bucket', dest='logBucket', help='Specify the S3 bucket containing AWS logs')
    parser.add_argument('-d', '--debug', action='store_true', dest='debug', help='Increase verbosity')
    parser.add_argument('-a', '--access_key', dest='access_key', help='S3 Access key credential')
    parser.add_argument('-k', '--secret_key', dest='secret_key', help='S3 Secrety key credential')
    #Beware, once you delete history it's gone.
    parser.add_argument('-R', '--remove', action='store_true', dest='deleteFile', help='Remove processed files from the AWS S3 bucket')
    options = parser.parse_args()
    db_connector = None

    if options.debug:
        global enable_debug
        enable_debug = True
        debug('+++ Debug mode on')

    if options.logBucket == None:
        print 'ERROR: Missing an AWS S3 bucket! (-b flag)'
        sys.exit(1)

    # Create or connect SQLite DB
    debug('+++ Create or connect SQLite DB')
    try:
        db_connector = sqlite3.connect("{0}/s3_cloudtrail.db".format(wazuh_wodle))
        db_connector.execute("select count(*) from log_progress")
    except sqlite3.OperationalError:
        db_connector.execute("create table log_progress  (log_name 'text' primary key, processed_date 'TEXT')")

    
    # Connect to Amazon S3 Bucket
    debug('+++ Connecting to Amazon S3')

    if options.access_key != None and options.secret_key != None:
        s3 = boto3.resource(
            's3',
            aws_access_key_id=options.access_key,
            aws_secret_access_key=options.secret_key
        )
    else:
        s3 = boto3.resource('s3')

    my_bucket = s3.Bucket(options.logBucket)
    try:
        s3.meta.client.head_bucket(Bucket=options.logBucket)
    except botocore.exceptions.ClientError as e:
        print "Bucket %s access error: %s" % (options.logBucket, e)
        sys.exit(3)

    for bucket_file in my_bucket.objects.all():
        downloaded_file = os.path.basename(str(bucket_file.key))
        downloaded_file_path = '{0}/{1}'.format(wazuh_tmp,downloaded_file)
        if re.match('.+_CloudTrail-Digest_.+', downloaded_file):
            debug('Skipping digest file: %s' % downloaded_file)
            continue
        if downloaded_file != "":
            if already_processed(downloaded_file, db_connector):
                debug("++ Skipping previously seen file {file}".format(file=downloaded_file))
                continue
            debug("++ Found new log: {0}".format(downloaded_file))
            my_bucket.download_file(bucket_file.key,downloaded_file_path)
            data = gzip.open(downloaded_file_path, 'rb')

            # Format JSON for Wazuh ingestion
            j = json.load(data)
            if "Records" not in j:
                continue
            for json_event in j["Records"]:
                aws_log = {}
                for key in json_event:
                    if json_event[key]:
                        aws_log[key] = json_event[key]
                aws_log['log_file'] = downloaded_file
                send_msg(wazuh_queue, header, aws_log)

            # Remove temporal file
            debug("+++ Removing temporal file: {0}".format(downloaded_file))

            try:
                os.remove(downloaded_file_path)
            except IOError as e:
                print "ERROR: Cannot delete %s (%s)" % (downloaded_file_path, e.strerror)

            # Remove file from S3 Bucket
            if options.deleteFile:
                debug("+++ Remove file from S3 Bucket:{0}".format(downloaded_file))
                s3.Object(options.logBucket, bucket_file.key).delete()
            mark_complete(downloaded_file, db_connector)

if __name__ == '__main__':
    signal.signal(signal.SIGINT, handler)
    main(sys.argv[1:])
    sys.exit(0)
