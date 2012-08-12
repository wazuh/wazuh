<?php
/* OSSEC 2 RSS script.
 * by Daniel B. Cid ( dcid @ ossec.net)
 *
 * Just upload it to any web-accessible directory, and make
 * sure the web server can access the OSSEC alerts log file.
 */


$ossec_log = "/var/ossec/logs/alerts/alerts.log";
if(!is_readable($ossec_log))
{
    echo "ERROR: Unable to access $ossec_log\n";
    echo "*TIP: Make sure your web server can access that file. \n";
    exit(1);
}

$timelp = filemtime($ossec_log);
$fh = fopen($ossec_log, "r");
if(!$fh)
{
    exit(1);
}

if(filesize($ossec_log) > 30000)
{
    fseek($fh, -30000, SEEK_END);
    $line = fgets($fh, 4096);
}


$lastlines = array();
$event = array();
while($line = fgets($fh, 4096))
{
    $line = trim($line);
    if($line == "")
    {
        continue;
    }

    if(strncmp($line, "** Alert ", 9) == 0)
    {
        if(strncmp($event, "** Alert ", 9) == 0)
        {
            array_push($lastlines, $event);
        }
        unset($event);
        $event = array();
        $event[] = htmlspecialchars($line);
    }
    else
    {
        $event[] = htmlspecialchars($line);
    }
}
fclose($fh);

$lastlines = array_reverse($lastlines);
$myhost = gethostname();
if($myhost === FALSE)
{
    $myhost = "";
}

echo '<?xml version="1.0" encoding="UTF-8"?>
<?xml-stylesheet href="/css/rss.css" type="text/css"?>
<rss version="2.0">
<channel>
<title>OSSEC '.$myhost.' RSS Feed</title>
<link>http://ossec.net</link>
<description>OSSEC RSS Feed for '.$myhost.'</description>
<language>en-us</language>
<lastBuildDate>'.date("r", $timelp).'</lastBuildDate>
<pubDate>'.date("r", $timelp).'</pubDate>
<copyright>(C) OSSEC.net 2008-2011</copyright>
<generator>OSSEC.net RSS feed</generator>
<ttl>30</ttl>
<webMaster>dcid@ossec.net</webMaster>

<image>
  <title>OSSEC Alert Feed</title>
  <url>http://www.ossec.net/img/ossec_logo.jpg</url>
  <link>http://ossec.net</link>
</image>
';

foreach($lastlines as $myentry)
{
echo $myentry;

    if(preg_match("/^.. Alert (\d+)\./", $myentry[0], $regs, PREG_OFFSET_CAPTURE, 0))
    {
        $myunixtime = $regs[1][0];
    }
    else
    {
        continue;
    }


    echo '
    <item>
        <title>'.$myentry[2]." ,from ".substr($myentry[1], 20).'</title>
        <link>http://ossec.net</link>
        <guid isPermaLink="false">'.$myentry[0].'</guid>
        <description><![CDATA[';

    foreach($myentry as $myline){ echo $myline."<br />\n"; }

    echo '
        ]]></description>
        <pubDate>'.date("r", $myunixtime).'</pubDate>
    </item>
    ';
}

echo '
</channel>
</rss>
';


?>
