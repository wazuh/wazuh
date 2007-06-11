
-- 
-- Table structure for table `acid_event`
-- 

CREATE TABLE `acid_event` (
  `sid` int(10) unsigned NOT NULL,
  `cid` int(10) unsigned NOT NULL,
  `signature` varchar(255) NOT NULL,
  `sig_name` varchar(255) default NULL,
  `sig_class_id` int(10) unsigned default NULL,
  `sig_priority` int(10) unsigned default NULL,
  `timestamp` datetime NOT NULL,
  `ip_src` int(10) unsigned default NULL,
  `ip_dst` int(10) unsigned default NULL,
  `ip_proto` int(11) default NULL,
  `layer4_sport` int(10) unsigned default NULL,
  `layer4_dport` int(10) unsigned default NULL,
  `username` varchar(255) default NULL,
  PRIMARY KEY  (`sid`,`cid`),
  KEY `signature` (`signature`),
  KEY `sig_name` (`sig_name`),
  KEY `sig_class_id` (`sig_class_id`),
  KEY `sig_priority` (`sig_priority`),
  KEY `timestamp` (`timestamp`),
  KEY `ip_src` (`ip_src`),
  KEY `ip_dst` (`ip_dst`),
  KEY `ip_proto` (`ip_proto`),
  KEY `layer4_sport` (`layer4_sport`),
  KEY `layer4_dport` (`layer4_dport`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

-- 
-- Table structure for table `data`
-- 

CREATE TABLE `data` (
  `sid` int(10) unsigned NOT NULL,
  `cid` int(10) unsigned NOT NULL,
  `data_payload` text,
  PRIMARY KEY  (`sid`,`cid`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

-- 
-- Table structure for table `event`
-- 

CREATE TABLE `event` (
  `sid` int(10) unsigned NOT NULL,
  `cid` int(10) unsigned NOT NULL,
  `signature` int(10) unsigned NOT NULL,
  `timestamp` datetime NOT NULL,
  PRIMARY KEY  (`sid`,`cid`),
  KEY `sig` (`signature`),
  KEY `time` (`timestamp`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

-- 
-- Table structure for table `sensor`
-- 

CREATE TABLE `sensor` (
  `sid` int(10) unsigned NOT NULL auto_increment,
  `hostname` text,
  `interface` text,
  `filter` text,
  `detail` tinyint(4) default NULL,
  `encoding` tinyint(4) default NULL,
  `last_cid` int(10) unsigned NOT NULL,
  PRIMARY KEY  (`sid`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1 AUTO_INCREMENT=6 ;

-- --------------------------------------------------------

-- 
-- Table structure for table `signature`
-- 

CREATE TABLE `signature` (
  `sig_id` int(10) unsigned NOT NULL auto_increment,
  `sig_name` varchar(255) NOT NULL,
  `sig_class_id` int(10) unsigned NOT NULL,
  `sig_priority` int(10) unsigned default NULL,
  `sig_rev` int(10) unsigned default NULL,
  `sig_sid` int(10) unsigned default NULL,
  `sig_gid` int(10) unsigned default NULL,
  PRIMARY KEY  (`sig_id`),
  KEY `sign_idx` (`sig_name`(20)),
  KEY `sig_class_id_idx` (`sig_class_id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1 AUTO_INCREMENT=47 ;
