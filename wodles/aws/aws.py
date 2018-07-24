#!/usr/bin/env python
#
# Import AWS CloudTrail
#
# Author: Wazuh, Inc.
# Copyright: GPLv3
#
# Updated by Jeremy Phillips <jeremy@uranusbytes.com>
# Full re-work of AWS wodle as per #510
# - Scalability and functional enhancements for parsing of CloudTrail
# - Support for existing config params
# - Upgrade to a granular object key addressing to support multiple CloudTrails in S3 bucket
# - Support granular parsing by account id, region, prefix
# - Support only parsing logs after a given date
# - Support IAM credential profiles, IAM roles
# - Only look for new logs/objects since last iteration
# - Skip digest files altogether (only look at logs)
# - Move from downloading object and working with file on filesystem to byte stream
# - Inherit debug from modulesd
# - Add bounds checks for msg against socket buffer size; truncate fields if too big (wazuh/wazuh#733)
# - Support multiple debug levels
# - Move connect error so not confused with general error
# - If fail to parse log, and skip_on_error, attempt to send me msg to wazuh
# - Support existing configurations by migrating data, inferring other required params
#
# Future
# ToDo: Integrity check logs against digest
# ToDo: Escape special characters in arguments?  Needed?
#     Valid values for AWS Keys
#     Alphanumeric characters [0-9a-zA-Z]
#     Special characters !, -, _, ., *, ', (, and )
#
# Error Codes:
#   1 - Unknown
#   2 - SIGINT
#   3 - Invalid credentials to access S3 bucket
#   4 - boto3 module missing
#   5 - Unexpected error accessing SQLite DB
#   6 - Unable to create SQLite DB
#   7 - Unexpected error querying/working with objects in S3
#   8 - Failed to decompress file
#   9 - Failed to parse file
#   10 - Failed to execute DB cleanup
#   11 - Unable to connect to Wazuh

import signal
import sys
import sqlite3
import argparse

from socket import socket, AF_UNIX, SOCK_DGRAM

try:
    import boto3
except ImportError:
    print('ERROR: No module found boto3.')
    sys.exit(4)
import botocore
import json
import zlib
from datetime import datetime

# Retain last X log processed records for each account/region; only last record is used; rest are for history/knowledge
retain_db_records = 100

# Message header
msg_header = '1:Wazuh-AWS:'

# Enable/disable debug mode
debug_level = 0
# Wazuh installation path
wazuh_path = open('/etc/ossec-init.conf').readline().split('"')[1]
# Wazuh queue
wazuh_queue = '{0}/queue/ossec/queue'.format(wazuh_path)
# Wazuh wodle path
wazuh_wodle = '{0}/wodles/aws'.format(wazuh_path)


def send_msg(wazuh_queue, queue_buffer, msg):
    formatted = {
        'integration': 'aws',
        'aws': msg
    }
    debug(json.dumps(formatted, indent=4), 3)
    formatted = '{0}{1}'.format(msg_header, json.dumps(formatted))
    formatted = formatted.encode()
    # if msg too large to send to socket
    for shrink in ['requestParameters', 'responseElements']:
        if len(formatted) > queue_buffer:
            debug('++ Message truncated because too large; removing {shrink}'.format(shrink=shrink), 2)
            msg[shrink] = 'Value truncated because too large for socket buffer'
            formatted = {
                'integration': 'aws',
                'aws': msg
            }
            formatted = '{0}{1}'.format(msg_header, json.dumps(formatted))
            formatted.encode()
        else:
            # Message not too large; skip out
            break

    s = socket(AF_UNIX, SOCK_DGRAM)
    try:
        s.connect(wazuh_queue)
    except:
        print('ERROR: Wazuh must be running.')
        sys.exit(11)
    s.send(formatted)
    s.close()


def handler(signal, frame):
    print "ERROR: SIGINT received, bye!"
    sys.exit(2)


def already_processed(downloaded_file, aws_account_id, aws_region, db_connector):
    if db_connector:
        cursor = db_connector.execute(
            """
              SELECT
                count(*) 
              FROM 
                trail_progress 
              WHERE 
                aws_account_id='{aws_account_id}' AND 
                aws_region='{aws_region}' AND 
                log_key='{log_name}'""".format(aws_account_id=aws_account_id,
                                               aws_region=aws_region,
                                               log_name=downloaded_file))
        if cursor.fetchone()[0]:
            return True
    return False


def mark_complete(aws_account_id, aws_region, log_key, db_connector):
    if db_connector:
        db_connector.execute(
            """
              INSERT INTO trail_progress (
                aws_account_id, 
                aws_region, 
                log_key, 
                processed_date) VALUES (
                '{aws_account_id}', 
                '{aws_region}', 
                '{log_key}', 
                DATETIME('now'))""".format(aws_account_id=aws_account_id,
                                           aws_region=aws_region,
                                           log_key=log_key))
        debug('+++ Mark log complete: {log_key}'.format(log_key=log_key), 2)
        db_connector.commit()


def debug(msg, msg_level):
    if debug_level >= msg_level:
        print('DEBUG: {debug_msg}'.format(debug_msg=msg))


def arg_valid_date(arg_string):
    try:
        parsed_date = datetime.strptime(arg_string, "%Y-%b-%d")
        # Return int created from date in YYYYMMDD format
        return int(parsed_date.strftime('%Y%m%d'))
    except ValueError:
        raise argparse.ArgumentTypeError("Argument not a valid date in format YYYY-MMM-DD: '{0}'.".format(arg_string))


def arg_valid_prefix(arg_string):
    if arg_string and arg_string[-1:] != '/':
        return '{arg_string}/'.format(arg_string=arg_string)
    return arg_string


def arg_valid_accountid(arg_string):
    if not arg_string:
        return []
    account_ids = arg_string.split(',')
    for account in account_ids:
        if not account.strip().isdigit() and len(account) != 12:
            raise argparse.ArgumentTypeError(
                "Not valid AWS account ID (numeric digits only): '{0}'.".format(arg_string))

    return account_ids


def arg_valid_regions(arg_string):
    if not arg_string:
        return []
    final_regions = []
    regions = arg_string.split(',')
    for arg_region in regions:
        if arg_region.strip():
            final_regions.append(arg_region.strip())
    return final_regions


def get_s3_client(options):
    conn_args = {}
    if options.access_key is not None and options.secret_key is not None:
        conn_args['aws_access_key_id'] = options.access_key
        conn_args['aws_secret_access_key'] = options.secret_key
    if options.aws_profile is not None:
        conn_args['profile_name'] = options.aws_profile

    boto_session = boto3.Session(**conn_args)

    # If using a role, create session using that
    if options.iam_role_arn:
        sts_client = boto_session.client('sts')
        sts_role_assumption = sts_client.assume_role(RoleArn=options.iam_role_arn,
                                                     RoleSessionName='WazuhCloudTrailLogParsing')
        sts_session = boto3.Session(aws_access_key_id=sts_role_assumption['Credentials']['AccessKeyId'],
                                    aws_secret_access_key=sts_role_assumption['Credentials']['SecretAccessKey'],
                                    aws_session_token=sts_role_assumption['Credentials']['SessionToken'])
        s3_client = sts_session.client(service_name='s3')
    else:
        s3_client = boto_session.client(service_name='s3')
    try:
        s3_client.head_bucket(Bucket=options.logBucket)
    except botocore.exceptions.ClientError as e:
        print "ERROR: Bucket %s access error: %s" % (options.logBucket, e)
        sys.exit(3)
    return s3_client


def marker_only_logs_after(options, aws_account_id, aws_region):
    only_logs_after = datetime.strptime(str(options.only_logs_after), "%Y%m%d")
    filter_marker = '{trail_prefix}AWSLogs/{aws_account_id}/CloudTrail/{aws_region}/{only_logs_after}'.format(
        trail_prefix=options.trail_prefix,
        aws_account_id=aws_account_id,
        aws_region=aws_region,
        only_logs_after=only_logs_after.strftime('%Y/%m/%d'))
    return filter_marker


def migrate_legacy_table(db_connector):
    debug('++ Query legacy table records', 1)
    query_results = db_connector.execute("""
                                           SELECT 
                                             log_name,
                                             processed_date 
                                           FROM 
                                             log_progress;""")
    for row in query_results:
        if row[0] != '':
            try:
                debug('++ Parse arguments from log file name', 2)
                filename_parts = row[0].split('_')
                aws_account_id = filename_parts[0]
                aws_region = filename_parts[2]
                log_timestamp = datetime.strptime(filename_parts[3].split('.')[0], '%Y%m%dT%H%M%SZ')
                log_key = 'AWSLogs/{aws_account_id}/CloudTrail/{aws_region}/{date_path}/{log_filename}'.format(
                    aws_account_id=aws_account_id,
                    aws_region=aws_region,
                    date_path=datetime.strftime(log_timestamp,'%Y/%m/%d'),
                    log_filename=row[0]
                )
                mark_complete(aws_account_id, aws_region, log_key, db_connector)
            except:
                debug('++ Error parsing log file name: {}'.format(row[0]), 1)

    # Rename legacy table
    debug('+++ Rename legacy table', 1)
    db_connector.execute(
        """
          ALTER TABLE log_progress
            RENAME TO legacy_log_progress;""")
    db_connector.commit()

    debug('+++ Finished legacy table migration', 1)
    return


def main(argv):
    # Parse arguments
    parser = argparse.ArgumentParser(usage="usage: %(prog)s [options]",
                                     version="%(prog)s 1.1",
                                     description="Wazuh wodle for monitoring of AWS CloudTrail logs in S3 bucket",
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-b', '--bucket', dest='logBucket', help='Specify the S3 bucket containing AWS CloudTrail logs',
                        action='store', required=True)
    parser.add_argument('-c', '--aws_account_id', dest='aws_account_id',
                        help='AWS Account ID for CloudTrail logs', required=True,
                        type=arg_valid_accountid)
    parser.add_argument('-d', '--debug', action='store', dest='debug', default=0, help='Enable debu')
    parser.add_argument('-a', '--access_key', dest='access_key', help='S3 Access key credential', default=None)
    parser.add_argument('-k', '--secret_key', dest='secret_key', help='S3 Secret key credential', default=None)
    # Beware, once you delete history it's gone.
    parser.add_argument('-R', '--remove', action='store_true', dest='deleteFile',
                        help='Remove processed files from the AWS S3 bucket', default=False)
    parser.add_argument('-p', '--aws_profile', dest='aws_profile', help='The name of credential profile to use',
                        default=None)
    parser.add_argument('-i', '--iam_role_arn', dest='iam_role_arn',
                        help='ARN of IAM role to assume for access to S3 bucket',
                        default=None)
    parser.add_argument('-n', '--aws_account_alias', dest='aws_account_alias',
                        help='AWS Account ID Alias', default='')
    parser.add_argument('-l', '--trail_prefix', dest='trail_prefix',
                        help='Log prefix for S3 key',
                        default='', type=arg_valid_prefix)
    parser.add_argument('-s', '--only_logs_after', dest='only_logs_after',
                        help='Only parse logs after this date - format YYYY-MMM-DD', default='1970-JAN-01',
                        type=arg_valid_date)
    parser.add_argument('-r', '--regions', dest='regions', help='Comma delimited list of AWS regions to parse logs',
                        default='', type=arg_valid_regions)
    parser.add_argument('-e', '--skip_on_error', action='store_true', dest='skip_on_error',
                        help='If fail to parse a file, error out instead of skipping the file', default=True)
    options = parser.parse_args()

    db_connector = None

    # Get socket buffer size
    with open('/proc/sys/net/core/rmem_max', 'r') as kernel_param:
        queue_buffer = int(kernel_param.read().strip())

    if int(options.debug) > 0:
        global debug_level
        debug_level = int(options.debug)
        debug('+++ Debug mode on - Level: {debug}'.format(debug=options.debug), 1)

    # Create or connect SQLite DB
    debug('+++ Connect SQLite DB', 1)
    legacy_table_exists = False
    table_exists = False
    try:
        db_connector = sqlite3.connect("{0}/s3_cloudtrail.db".format(wazuh_wodle))
        query_results = db_connector.execute("""
                                               SELECT 
                                                 tbl_name 
                                               FROM 
                                                 sqlite_master 
                                               WHERE 
                                                 type='table';""")
        for row in query_results:
            if row[0] == 'log_progress':
                legacy_table_exists = True
            elif row[0] == 'trail_progress':
                table_exists = True
        if not table_exists:
            raise sqlite3.OperationalError
        db_exists = True
    except sqlite3.OperationalError:
        db_exists = False
    except:
        print "ERROR: Unexpected error accessing SQLite DB"
        sys.exit(5)

    # DB does exist yet
    if not db_exists:
        try:
            debug('+++ Table does not exist; create', 1)
            db_connector.execute(
                """
                  CREATE TABLE
                    trail_progress (
                      aws_account_id 'text' NOT NULL, 
                      aws_region 'text' NOT NULL, 
                      log_key 'text' NOT NULL, 
                      processed_date 'text' NOT NULL, 
                      PRIMARY KEY (aws_account_id, aws_region, log_key));""")
            db_connector.commit()
        except:
            print "ERROR: Unable to create SQLite DB"
            sys.exit(6)

    # Legacy table exists; migrate progress to new table
    if legacy_table_exists:
        debug('+++ Migrate legacy table data', 1)
        migrate_legacy_table(db_connector)

    # Connect to Amazon S3 Bucket
    s3_client = get_s3_client(options)
    debug('+++ Connecting to Amazon S3', 1)

    # No accounts provided, so find which exist in s3 bucket
    if not options.aws_account_id:
        for common_prefix in s3_client.list_objects_v2(Bucket=options.logBucket,
                                                       Prefix='{trail_prefix}AWSLogs/'.format(
                                                           trail_prefix=options.trail_prefix),
                                                       Delimiter='/')['CommonPrefixes']:
            if common_prefix['Prefix'].split('/')[-2].isdigit():
                options.aws_account_id.append(common_prefix['Prefix'].split('/')[-2])

    for aws_account_id in options.aws_account_id:
        # No regions provided, so find which exist for this AWS account
        if options.regions:
            aws_account_regions = options.regions
        else:
            aws_account_regions = []
            regions_in_s3 = s3_client.list_objects_v2(Bucket=options.logBucket,
                                                           Prefix='{trail_prefix}AWSLogs/{aws_account_id}/CloudTrail/'.format(
                                                               trail_prefix=options.trail_prefix,
                                                               aws_account_id=aws_account_id),
                                                           Delimiter='/')
            if 'CommonPrefixes' in regions_in_s3:
                for common_prefix in regions_in_s3['CommonPrefixes']:
                    aws_account_regions.append(common_prefix['Prefix'].split('/')[-2])
            else:
                debug('+++ No regions found for AWS account: {aws_account_id}'.format(aws_account_id=aws_account_id), 1)
                continue

        for aws_region in aws_account_regions:
            debug('+++ Working on {aws_account_id} - {aws_region}'.format(aws_account_id=aws_account_id,
                                                                          aws_region=aws_region), 1)
            # Where did we end last run thru on this account/region?
            query_results = db_connector.execute(
                """
                  SELECT 
                    log_key 
                  FROM 
                    trail_progress 
                  WHERE 
                    aws_account_id='{aws_account_id}' AND 
                    aws_region = '{aws_region}' 
                  ORDER BY 
                    ROWID DESC 
                  LIMIT 1;""".format(aws_account_id=aws_account_id,
                                     aws_region=aws_region))
            try:
                filter_marker = query_results.fetchone()[0]
                # Existing logs processed, but older than only_logs_after
                if int(filter_marker.split('/')[-1].split('_')[-2].split('T')[0]) < options.only_logs_after:
                    filter_marker = marker_only_logs_after(options, aws_account_id, aws_region)
            except TypeError:
                # No logs processed for this account/region, but if only_logs_after has been set
                if options.only_logs_after:
                    filter_marker = marker_only_logs_after(options, aws_account_id, aws_region)
                else:
                    filter_marker = ''

            filter_args = {
                'Bucket': options.logBucket,
                'MaxKeys': 1000,
                'Prefix': '{trail_prefix}AWSLogs/{aws_account_id}/CloudTrail/{aws_region}/'.format(
                    trail_prefix=options.trail_prefix, aws_account_id=aws_account_id, aws_region=aws_region)
            }
            if filter_marker:
                filter_args['StartAfter'] = filter_marker
                debug('+++ Marker: {0}'.format(filter_marker), 2)

            try:
                bucket_files = s3_client.list_objects_v2(**filter_args)
                if 'Contents' not in bucket_files:
                    debug('+++ No logs to process: {aws_account_id}/{aws_region}'.format(aws_account_id=aws_account_id,
                                                                                         aws_region=aws_region), 1)
                    continue

                for bucket_file in s3_client.list_objects_v2(**filter_args)['Contents']:
                    if bucket_file['Key'] != "":
                        # Fail safe in case an older log gets thru StartAfter; probably redundant
                        if int(bucket_file['Key'].split('/')[-1].split('_')[-2].split('T')[0]) < options.only_logs_after:
                            debug("++ Skipping file dated before only_logs_after: {file}".format(file=bucket_file['Key']), 1)
                            mark_complete(aws_account_id, aws_region, bucket_file['Key'], db_connector)
                            continue
                        if already_processed(bucket_file['Key'], aws_account_id, aws_region, db_connector):
                            debug("++ Skipping previously processed file {file}".format(file=bucket_file['Key']), 1)
                            continue
                        debug("++ Found new log: {0}".format(bucket_file['Key']), 2)

                        try:
                            raw_gz_object = s3_client.get_object(Bucket=options.logBucket, Key=bucket_file['Key'])['Body']
                            uncompressed_object = zlib.decompress(raw_gz_object.read(), 16 + zlib.MAX_WBITS)
                        except:
                            if options.skip_on_error:
                                debug("++ Failed to decompress file; skipping...", 1)
                                try:
                                    error_msg = {
                                        'eventSource'
                                    }
                                    send_msg(wazuh_queue, queue_buffer, aws_log)
                                except:
                                    debug("++ Failed to send message to Wazuh", 1)
                            else:
                                print "ERROR: Failed to decompress file: {0}".format(bucket_file['Key'])
                                sys.exit(8)

                        try:
                            j = json.loads(uncompressed_object)
                        except:
                            if options.skip_on_error:
                                debug("++ Unable to parse file {0}; skipping...".format(bucket_file['Key']), 1)
                                try:
                                    error_msg = {}
                                    send_msg(wazuh_queue, queue_buffer, aws_log)
                                except:
                                    debug("++ Failed to send message to Wazuh", 1)
                            else:
                                print "ERROR: Failed to parse file: {0}".format(bucket_file['Key'])
                                sys.exit(9)
                        if "Records" not in j:
                            continue
                        for cloudtrail_event in j["Records"]:
                            # Parse out all the values of 'None'
                            aws_log = dict((key, value) for key, value in cloudtrail_event.iteritems() if value)
                            aws_log['log_file'] = bucket_file['Key']
                            aws_log['aws_account_alias'] = options.aws_account_alias
                            send_msg(wazuh_queue, queue_buffer, aws_log)

                        # Remove file from S3 Bucket
                        if options.deleteFile:
                            debug("+++ Remove file from S3 Bucket:{0}".format(bucket_file['Key']), 2)
                            s3_client.delete_object(Bucket=options.logBucket, Key=bucket_file['Key'])
                        mark_complete(aws_account_id, aws_region, bucket_file['Key'], db_connector)
            except SystemExit:
                raise
            except:
                print "ERROR: Unexpected error querying/working with objects in S3"
                sys.exit(7)

            debug("+++ DB Maintenance", 1)
            # Delete all the older log processed records for account/region
            try:
                db_connector.execute(
                    """DELETE
                       FROM 
                         trail_progress 
                       WHERE
                         aws_account_id='{aws_account_id}' AND 
                         aws_region='{aws_region}' AND 
                         rowid NOT IN 
                           (SELECT ROWID 
                            FROM 
                              trail_progress
                            WHERE 
                              aws_account_id='{aws_account_id}' AND 
                              aws_region='{aws_region}'
                            ORDER BY
                              ROWID DESC
                            LIMIT {retain_db_records})""".format(aws_account_id=aws_account_id,
                                                                 aws_region=aws_region,
                                                                 retain_db_records=retain_db_records))
                db_connector.commit()
            except:
                print "ERROR: Failed to execute DB cleanup - AWS Account ID: {aws_account_id}  Region: {aws_region}".format(aws_account_id=aws_account_id,
                                                                 aws_region=aws_region)
                sys.exit(10)

    db_connector.execute('PRAGMA optimize;')
    db_connector.close()


if __name__ == '__main__':
    debug('Args: {args}'.format(args=str(sys.argv)), 2)
    signal.signal(signal.SIGINT, handler)
    main(sys.argv[1:])
    sys.exit(0)
