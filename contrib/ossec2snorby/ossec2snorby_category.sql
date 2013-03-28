/*
Navicat MySQL Data Transfer

Source Server         : generic-localhost
Source Server Version : 50167
Source Host           : localhost:3306
Source Database       : snorby

Target Server Type    : MYSQL
Target Server Version : 50167
File Encoding         : 65001

Date: 2013-01-28 16:35:59
*/

SET FOREIGN_KEY_CHECKS=0;
-- ----------------------------
-- Table structure for `category`
-- ----------------------------
DROP TABLE IF EXISTS `category`;
CREATE TABLE `category` (
  `cat_id` smallint(5) unsigned NOT NULL AUTO_INCREMENT,
  `sig_class_id` smallint(5) NOT NULL,
  `cat_name` varchar(32) NOT NULL,
  PRIMARY KEY (`cat_id`),
  UNIQUE KEY `cat_name` (`cat_name`),
  KEY `cat_name_2` (`cat_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- ----------------------------
-- Records of category
-- ----------------------------
INSERT INTO `category` VALUES ('1', '1', 'syslog');
INSERT INTO `category` VALUES ('2', '29', 'firewall');
INSERT INTO `category` VALUES ('3', '29', 'ids');
INSERT INTO `category` VALUES ('4', '1', 'web-log');
INSERT INTO `category` VALUES ('5', '1', 'squid');
INSERT INTO `category` VALUES ('6', '1', 'windows');
INSERT INTO `category` VALUES ('7', '1', 'ossec');
INSERT INTO `category` VALUES ('8', '9', 'pam');
INSERT INTO `category` VALUES ('9', '11', 'authentication_success');
INSERT INTO `category` VALUES ('10', '18', 'authentication_failed');
INSERT INTO `category` VALUES ('11', '18', 'invalid_login');
INSERT INTO `category` VALUES ('12', '18', 'authentication_failures');
INSERT INTO `category` VALUES ('13', '1', 'sshd');
INSERT INTO `category` VALUES ('14', '4', 'recon');
INSERT INTO `category` VALUES ('15', '28', 'exploit_attempt');
INSERT INTO `category` VALUES ('16', '1', 'telnetd');
INSERT INTO `category` VALUES ('17', '3', 'errors');
INSERT INTO `category` VALUES ('18', '29', 'low_diskspace');
INSERT INTO `category` VALUES ('19', '29', 'service_availability');
INSERT INTO `category` VALUES ('20', '29', 'nfs');
INSERT INTO `category` VALUES ('21', '29', 'xinetd');
INSERT INTO `category` VALUES ('22', '29', 'access_control');
INSERT INTO `category` VALUES ('23', '18', 'access_denied');
INSERT INTO `category` VALUES ('24', '22', 'connection_attempt');
INSERT INTO `category` VALUES ('25', '1', 'mail');
INSERT INTO `category` VALUES ('26', '1', 'smartd');
INSERT INTO `category` VALUES ('27', '1', 'linuxkernel');
INSERT INTO `category` VALUES ('28', '1', 'promisc');
INSERT INTO `category` VALUES ('29', '1', 'system_shutdown');
INSERT INTO `category` VALUES ('30', '1', 'cron');
INSERT INTO `category` VALUES ('31', '19', 'su');
INSERT INTO `category` VALUES ('32', '1', 'tripwire');
INSERT INTO `category` VALUES ('33', '1', 'adduser');
INSERT INTO `category` VALUES ('34', '19', 'sudo');
INSERT INTO `category` VALUES ('35', '29', 'pptp');
INSERT INTO `category` VALUES ('36', '1', 'fts');
INSERT INTO `category` VALUES ('37', '1', 'dpkg');
INSERT INTO `category` VALUES ('38', '1', 'config_changed');
INSERT INTO `category` VALUES ('39', '1', 'yum');
INSERT INTO `category` VALUES ('40', '29', 'arpwatch');
INSERT INTO `category` VALUES ('41', '29', 'new_host');
INSERT INTO `category` VALUES ('42', '30', 'ip_spoof');
INSERT INTO `category` VALUES ('43', '1', 'symantec');
INSERT INTO `category` VALUES ('44', '17', 'virus');
INSERT INTO `category` VALUES ('45', '29', 'pix');
INSERT INTO `category` VALUES ('46', '1', 'account_changed');
INSERT INTO `category` VALUES ('47', '3', 'system_error');
INSERT INTO `category` VALUES ('48', '1', 'named');
INSERT INTO `category` VALUES ('49', '10', 'invalid_access');
INSERT INTO `category` VALUES ('50', '3', 'client_misconfig');
INSERT INTO `category` VALUES ('51', '29', 'smbd');
INSERT INTO `category` VALUES ('52', '29', 'vsftpd');
INSERT INTO `category` VALUES ('53', '29', 'pure-ftpd');
INSERT INTO `category` VALUES ('54', '29', 'proftpd');
INSERT INTO `category` VALUES ('55', '29', 'msftp');
INSERT INTO `category` VALUES ('56', '29', 'ftpd');
INSERT INTO `category` VALUES ('57', '29', 'hordeimp');
INSERT INTO `category` VALUES ('58', '29', 'roundcube');
INSERT INTO `category` VALUES ('59', '1', 'wordpress');
INSERT INTO `category` VALUES ('60', '29', 'cimserver');
INSERT INTO `category` VALUES ('61', '29', 'vpopmail');
INSERT INTO `category` VALUES ('62', '29', 'vm-pop3d');
INSERT INTO `category` VALUES ('63', '29', 'courier');
INSERT INTO `category` VALUES ('64', '29', 'web');
INSERT INTO `category` VALUES ('65', '1', 'accesslog');
INSERT INTO `category` VALUES ('66', '28', 'attack');
INSERT INTO `category` VALUES ('67', '30', 'sql_injection');
INSERT INTO `category` VALUES ('68', '27', 'web_scan');
INSERT INTO `category` VALUES ('69', '29', 'appsec');
INSERT INTO `category` VALUES ('70', '29', 'apache');
INSERT INTO `category` VALUES ('71', '22', 'automatic_attack');
INSERT INTO `category` VALUES ('72', '22', 'unknown_resource');
INSERT INTO `category` VALUES ('73', '3', 'invalid_request');
INSERT INTO `category` VALUES ('74', '1', 'mysql_log');
INSERT INTO `category` VALUES ('75', '1', 'postgresql_log');
INSERT INTO `category` VALUES ('76', '29', 'firewall_drop');
INSERT INTO `category` VALUES ('77', '23', 'multiple_drops');
INSERT INTO `category` VALUES ('78', '29', 'cisco_ios');
INSERT INTO `category` VALUES ('79', '29', 'netscreenfw');
INSERT INTO `category` VALUES ('80', '29', 'sonicwall');
INSERT INTO `category` VALUES ('81', '1', 'postfix');
INSERT INTO `category` VALUES ('82', '32', 'spam');
INSERT INTO `category` VALUES ('83', '32', 'multiple_spam');
INSERT INTO `category` VALUES ('84', '29', 'sendmail');
INSERT INTO `category` VALUES ('85', '29', 'smf-sav');
INSERT INTO `category` VALUES ('86', '29', 'imapd');
INSERT INTO `category` VALUES ('87', '29', 'mailscanner');
INSERT INTO `category` VALUES ('88', '29', 'dovecot');
INSERT INTO `category` VALUES ('89', '29', 'ms');
INSERT INTO `category` VALUES ('90', '29', 'exchange');
INSERT INTO `category` VALUES ('91', '29', 'racoon');
INSERT INTO `category` VALUES ('92', '29', 'cisco_vpn');
INSERT INTO `category` VALUES ('93', '29', 'spamd');
INSERT INTO `category` VALUES ('94', '10', 'win_authentication_failed');
INSERT INTO `category` VALUES ('95', '1', 'policy_changed');
INSERT INTO `category` VALUES ('96', '1', 'group_changed');
INSERT INTO `category` VALUES ('97', '1', 'win_group_changed');
INSERT INTO `category` VALUES ('98', '1', 'logs_cleared');
INSERT INTO `category` VALUES ('99', '1', 'login_denied');
INSERT INTO `category` VALUES ('100', '1', 'time_changed');
INSERT INTO `category` VALUES ('101', '1', 'group_created');
INSERT INTO `category` VALUES ('102', '1', 'win_group_created');
INSERT INTO `category` VALUES ('103', '2', 'group_deleted');
INSERT INTO `category` VALUES ('104', '2', 'win_group_deleted');
INSERT INTO `category` VALUES ('105', '30', 'attacks');
INSERT INTO `category` VALUES ('106', '1', 'mcafee');
INSERT INTO `category` VALUES ('107', '1', 'trend_micro');
INSERT INTO `category` VALUES ('108', '1', 'ocse');
INSERT INTO `category` VALUES ('109', '1', 'ocsevirus');
INSERT INTO `category` VALUES ('110', '1', 'mse');
INSERT INTO `category` VALUES ('111', '30', 'zeus');
INSERT INTO `category` VALUES ('112', '1', 'solaris_bsm');
INSERT INTO `category` VALUES ('113', '1', 'vmware');
INSERT INTO `category` VALUES ('114', '29', 'dhcp');
INSERT INTO `category` VALUES ('115', '1', 'service_start');
INSERT INTO `category` VALUES ('116', '29', 'dhcp_lease_action');
INSERT INTO `category` VALUES ('117', '29', 'dhcp_dns_maintenance');
INSERT INTO `category` VALUES ('118', '29', 'dhcp_maintenance');
INSERT INTO `category` VALUES ('119', '30', 'dhcp_rogue_server');
INSERT INTO `category` VALUES ('120', '29', 'dhcp_ipv6');
INSERT INTO `category` VALUES ('121', '29', 'asterisk');
INSERT INTO `category` VALUES ('122', '1', 'rootcheck');
INSERT INTO `category` VALUES ('123', '1', 'syscheck');
INSERT INTO `category` VALUES ('124', '1', 'process_monitor');
INSERT INTO `category` VALUES ('125', '1', 'agentless');
INSERT INTO `category` VALUES ('126', '1', 'hostinfo');
INSERT INTO `category` VALUES ('127', '1', 'active_response');
INSERT INTO `category` VALUES ('128', '13', 'elevation_of_privilege');
INSERT INTO `category` VALUES ('129', '1', 'local');
INSERT INTO `category` VALUES ('130', '1', 'openbsd');
INSERT INTO `category` VALUES ('131', '1', 'openbsdgroupdel');
INSERT INTO `category` VALUES ('132', '1', 'clamd');
INSERT INTO `category` VALUES ('133', '1', 'freshclam');
INSERT INTO `category` VALUES ('134', '1', 'bro');
INSERT INTO `category` VALUES ('135', '30', 'dropbear');
INSERT INTO `category` VALUES ('136', '30', 'dropbearauthentication_failed');
INSERT INTO `category` VALUES ('137', '4', 'dropbearauthentication_failures');
INSERT INTO `category` VALUES ('138', '4', 'dropbearrecon');
INSERT INTO `category` VALUES ('139', '5', 'dropbearauthentication_success');
