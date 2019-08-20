#!C:\Perl\bin\perl.exe

use CGI;
use Fcntl qw(:mode :flock SEEK_END);
use strict;
use warnings;

# -----------------------------------------------------------------------------------
#
# This is a CGI script that expects to be invoked by a web server, such as
# Apache HTTP Server. This script has three configuration options that
# require attention:
#
# - reports_directory
# - log_path
# - max_upload_size_mb
#
# Information about these options is below:
#
# Once this script is deployed, visit it in a web browser to confirm it is
# configured properly. For example:
#
#  http://internal.web.server/ciscat_https_report_receiver.pl?setup=1
#
# If the script outputs 'Report saving appears to be functional.' then it's
# ready for use.
#
# Note: Errors related to logging are not critical. Therefore, informational
# messages regarding the misconfiguration of logging may also be presnt. It is
# recommended that logging-related errors be resolved.
#
# Once this script is functional, CISCAT can send any of its configured reports to it. 
#
# For example:
#  ./CIS-CAT.sh -b benchmarks/CIS_Red_Hat_Enterprise_Linux_6_Benchmark_v2.0.0 -x -t -csv -u https://intranet/ciscat_https_report_receiver.pl 
#
# Will configure CIS-CAT to generate HTML, XML, Text and CSV reports and post them all to the URL.
#
# See the CIS_CAT Users Guide for a complete list of CISCAT's command line options.
#
# -----------------------------------------------------------------------------------

#
# CONFIGURATION OPTION: Location to store received reports.
#
# - This directory must be +r and +w by the user or group this script executes as.
# - Do not set $reports_directory to a directory that is accessible via the web server.
#

my $reports_directory = 'C:\\Users\\username\\Documents\\http_report_uploads';

#
# CONFIGURATION OPTION: Location of upload activity log.
#
# - This directory must be +r and +w by the user or group this script executes as.
# - Do not log_path to a location that is accessible via the web server.
#

my $log_path = 'C:\\Users\\username\\Documents\\ciscat_report_sink.log';

#
# CONFIGURATION OPTION: Maximum size of upload.
#
# - If this value is set too low, all reports will be blank.
# - If this value is set too high, opportunity to consume resources increases.

my $max_upload_size_mb = 15;

#
#
# ------ NO FURTHER CONFIGURATION REQUIRED ------
#
#

my $remote_ip = $ENV{'REMOTE_ADDR'};

sub log_request
{
        my $level       = shift;
        my $message     = shift;

        print "$level: $message<br/>";

        # Open log file for appending.
        if (! open(LOG, ">>$log_path") )
        {
                print "INFO: Can't open log file for writing - $!. Ensure log path exists and is writable by this script.<br/>";
                return;
        }

        # Obtain exclusive lock on log file.
        if (! flock(LOG, LOCK_EX) )
        {
                print "INFO: Can't lock log file - $!<br/>";
                return;
        }

        # Seek to the end of the file in case the log has be written to since we opened it.
        if (! seek(LOG,0, SEEK_END) )
        {
                print "INFO: Can't seek log file - $!<br/>";
                return;
        }

        # Ensure message does not contain double quotes. Double quotes would impact ability to parse the log file.
        $message =~ s/"/'/g;

        print LOG scalar localtime() . ",$level,$remote_ip,\"$message\"\n";

        # Unlock log file and close handle
        flock(LOG, LOCK_UN);
        close (LOG);

        return;
}

#
# Set maximum upload size.
#

$CGI::POST_MAX = 1024 * 1024 * $max_upload_size_mb;

#
# Begin output processing...
#

print "Content-type: text/html\n\n";

my $cgi = new CGI();
my $report = $cgi->param('ciscat-report');
my $setup = $cgi->param('setup');
my $report_name = $cgi->param('report-name');

if ( defined($setup) )
{

        # provide fake report contents to test with.
        $report = '<?xml version="1.0" encoding="UTF-8"?>Test';

        my $mode = undef;

        #
        # Confirm permission on report directory prevent o+r and o+w
        #


        if ( -d $reports_directory )
        {


                $mode = (stat($reports_directory))[2];

                if ( ($mode & S_IWOTH) > 0 )
                {
                        log_request("INFO", "Report directory is world writable. It shouldn't be.");
                }

                $mode = (stat($reports_directory))[2];

                if ( ($mode & S_IROTH) > 0 )
                {
                        log_request("INFO", "Report directory is world readable. It shouldn't be.");
                }

        }

        #
        # Confirm permission on log file prevent o+r and o+w
        #

        if ( -e $log_path )
        {
                $mode = (stat($log_path))[2];

                if ( ($mode & S_IWOTH) > 0 )
                {
                        log_request("INFO", "Log file is world writable. It shouldn't be.");
                }

                $mode = (stat($log_path))[2];

                if ( ($mode & S_IROTH) > 0 )
                {
                        log_request("INFO", "Log file is world readable. It shouldn't be.");
                }
        }

}

#
# Ensure report content has been provided.
#

if ( ! defined($report) )
{
        log_request("ERROR", "No report provided or report is too large.");
        exit(-1);
}

#
# Configure the report path...
#

my $report_path = "";
if ( ! defined($setup) )
{
	$report_path = $reports_directory . "\\" . $report_name;
}
else
{
	$report_path = $reports_directory . "\\Setup.txt";
}

#
# Open file to write report into.
#

if (! open(OUTFILE, ">$report_path") )
{
        log_request("ERROR", "Can't open report for writing - $!. Ensure report directory exists and is writable by this script.");
        exit(-1);
}

#
# Write report to file.
#

print OUTFILE $report;

#
# Set permissions on report
#

chmod(0400, $report_path);

#
# Close file
#

close(OUTFILE);



if ( defined($setup) )
{
        log_request("INFO", "Report saving appears to be functional.");
}
else
{
        log_request("INFO", "File ($report_name) uploaded.");
}

