CREATE DATABASE `ossec` DEFAULT CHARACTER SET latin1 COLLATE latin1_swedish_ci;
USE ossec;

CREATE TABLE `alerts` (
  `code` varchar(250) NOT NULL,
  `date` timestamp NOT NULL default CURRENT_TIMESTAMP on update CURRENT_TIMESTAMP,
  `agent` varchar(150) NOT NULL,
  `logfile` varchar(150) NOT NULL,
  `host` varchar(150) NOT NULL,
  `rule` smallint(6) default NULL,
  `level` tinyint(2) NOT NULL,
  `description` text,
  `source` varchar(15) default NULL,
  `user` varchar(15) NOT NULL,
  PRIMARY KEY  (`code`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
