target "activemq-mock" {
  name       = "activemq-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/activemq-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/activemq-mock:${variant}"]
}
target "cacti-mock" {
  name       = "cacti-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/cacti-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/cacti-mock:${variant}"]
}
target "chamilo-mock" {
  name       = "chamilo-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/chamilo-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/chamilo-mock:${variant}"]
}
target "cleo-mock" {
  name       = "cleo-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/cleo-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/cleo-mock:${variant}"]
}
target "coldfusion-mock" {
  name       = "coldfusion-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/coldfusion-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/coldfusion-mock:${variant}"]
}
target "craftcms-mock" {
  name       = "craftcms-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/craftcms-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/craftcms-mock:${variant}"]
}
target "crushftp-mock" {
  name       = "crushftp-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/crushftp-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/crushftp-mock:${variant}"]
}
target "drupal-sqli-mock" {
  name       = "drupal-sqli-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/drupal-sqli-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/drupal-sqli-mock:${variant}"]
}
target "ektron-mock" {
  name       = "ektron-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/ektron-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/ektron-mock:${variant}"]
}
target "exchange-mock" {
  name       = "exchange-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/exchange-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/exchange-mock:${variant}"]
}
target "geoserver-mock" {
  name       = "geoserver-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/geoserver-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/geoserver-mock:${variant}"]
}
target "goanywhere-mock" {
  name       = "goanywhere-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/goanywhere-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/goanywhere-mock:${variant}"]
}
target "grafana-mock" {
  name       = "grafana-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/grafana-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/grafana-mock:${variant}"]
}
target "hfs-mock" {
  name       = "hfs-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/hfs-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/hfs-mock:${variant}"]
}
target "ingress-nginx-mock" {
  name       = "ingress-nginx-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/ingress-nginx-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/ingress-nginx-mock:${variant}"]
}
target "log4shell-mock" {
  name       = "log4shell-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/log4shell-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/log4shell-mock:${variant}"]
}
target "manageengine-mock" {
  name       = "manageengine-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/manageengine-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/manageengine-mock:${variant}"]
}
target "minio-mock" {
  name       = "minio-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/minio-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/minio-mock:${variant}"]
}
target "moveit-mock" {
  name       = "moveit-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/moveit-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/moveit-mock:${variant}"]
}
target "nextjs-mock" {
  name       = "nextjs-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/nextjs-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/nextjs-mock:${variant}"]
}
target "owncloud-graphapi-mock" {
  name       = "owncloud-graphapi-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/owncloud-graphapi-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/owncloud-graphapi-mock:${variant}"]
}
target "pulse-secure-mock" {
  name       = "pulse-secure-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/pulse-secure-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/pulse-secure-mock:${variant}"]
}
target "screenconnect-mock" {
  name       = "screenconnect-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/screenconnect-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/screenconnect-mock:${variant}"]
}
target "spring4shell-mock" {
  name       = "spring4shell-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/spring4shell-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/spring4shell-mock:${variant}"]
}
target "struts-mock" {
  name       = "struts-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/struts-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/struts-mock:${variant}"]
}
target "superset-mock" {
  name       = "superset-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/superset-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/superset-mock:${variant}"]
}
target "telerik-report-mock" {
  name       = "telerik-report-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/telerik-report-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/telerik-report-mock:${variant}"]
}
target "tomcat-put-mock" {
  name       = "tomcat-put-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/tomcat-put-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/tomcat-put-mock:${variant}"]
}
target "vcenter-vsan-mock" {
  name       = "vcenter-vsan-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/vcenter-vsan-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/vcenter-vsan-mock:${variant}"]
}
target "zimbra-mock" {
  name       = "zimbra-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/zimbra-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/zimbra-mock:${variant}"]
}
target "vbulletin-widget-mock" {
  name       = "vbulletin-widget-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/vbulletin-widget-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/vbulletin-widget-mock:${variant}"]
}
target "twonky-mock" {
  name       = "twonky-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/twonky-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/twonky-mock:${variant}"]
}
target "eyesofnetwork-mock" {
  name       = "eyesofnetwork-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/eyesofnetwork-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/eyesofnetwork-mock:${variant}"]
}
target "unraid-mock" {
  name       = "unraid-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/unraid-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/unraid-mock:${variant}"]
}
target "movabletype-mock" {
  name       = "movabletype-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/movabletype-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/movabletype-mock:${variant}"]
}

target "gitlist-mock" {
  name       = "gitlist-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/gitlist-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/gitlist-mock:${variant}"]
}

target "symantec-sepm-mock" {
  name       = "symantec-sepm-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/symantec-sepm-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/symantec-sepm-mock:${variant}"]
}
target "civicrm-mock" {
  name       = "civicrm-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/civicrm-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/civicrm-mock:${variant}"]

}
target "joomla-contenthistory-mock" {
  name       = "joomla-contenthistory-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/joomla-contenthistory-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/joomla-contenthistory-mock:${variant}"]
}
target "pragyan-cms-mock" {
  name       = "pragyan-cms-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/pragyan-cms-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/pragyan-cms-mock:${variant}"]
}
target "simple-ads-manager-mock" {
  name       = "simple-ads-manager-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/simple-ads-manager-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/simple-ads-manager-mock:${variant}"]
}
target "livelycart-mock" {
  name       = "livelycart-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/livelycart-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/livelycart-mock:${variant}"]
}
target "joomla-eq-calendar-mock" {
  name       = "joomla-eq-calendar-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/joomla-eq-calendar-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/joomla-eq-calendar-mock:${variant}"]
}
target "vbulletin-forumrunner-mock" {
  name       = "vbulletin-forumrunner-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/vbulletin-forumrunner-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/vbulletin-forumrunner-mock:${variant}"]
}
target "navis-webaccess-mock" {
  name       = "navis-webaccess-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/navis-webaccess-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/navis-webaccess-mock:${variant}"]
}
target "peplink-balance-mock" {
  name       = "peplink-balance-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/peplink-balance-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/peplink-balance-mock:${variant}"]
}
target "merak-webmail-mock" {
  name       = "merak-webmail-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/merak-webmail-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/merak-webmail-mock:${variant}"]
}
target "password-protect-mock" {
  name       = "password-protect-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/password-protect-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/password-protect-mock:${variant}"]
}
target "backupbuddy-mock" {
  name       = "backupbuddy-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/backupbuddy-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/backupbuddy-mock:${variant}"]
}
target "netgear-prosafe-mock" {
  name       = "netgear-prosafe-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/netgear-prosafe-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/netgear-prosafe-mock:${variant}"]
}
target "vivotek-mock" {
  name       = "vivotek-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/vivotek-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/vivotek-mock:${variant}"]
}
target "php-nuke-mock" {
  name       = "php-nuke-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/php-nuke-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/php-nuke-mock:${variant}"]
}
target "zte-zxdsl-mock" {
  name       = "zte-zxdsl-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/zte-zxdsl-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/zte-zxdsl-mock:${variant}"]
}
target "servision-mock" {
  name       = "servision-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/servision-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/servision-mock:${variant}"]
}
target "splunk-mock" {
  name       = "splunk-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/splunk-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/splunk-mock:${variant}"]
}
target "quantum-mock" {
  name       = "quantum-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/quantum-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/quantum-mock:${variant}"]
}
target "canon-11692-mock" {
  name       = "canon-11692-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/canon-11692-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/canon-11692-mock:${variant}"]
}
target "solarwinds-srm-mock" {
  name       = "solarwinds-srm-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/solarwinds-srm-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/solarwinds-srm-mock:${variant}"]
}
target "brother-mock" {
  name       = "brother-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/brother-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/brother-mock:${variant}"]
}
target "canon-lbp6030w-mock" {
  name       = "canon-lbp6030w-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/canon-lbp6030w-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/canon-lbp6030w-mock:${variant}"]

}
target "lexmark-mock" {
  name       = "lexmark-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/lexmark-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/lexmark-mock:${variant}"]
}
target "netgear-readynas-mock" {
  name       = "netgear-readynas-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/netgear-readynas-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/netgear-readynas-mock:${variant}"]
}
target "cups-mock" {
  name       = "cups-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/cups-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/cups-mock:${variant}"]
}
target "struts-2248-mock" {
  name       = "struts-2248-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/struts-2248-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/struts-2248-mock:${variant}"]
}
target "cotonti-mock" {
  name       = "cotonti-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/cotonti-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/cotonti-mock:${variant}"]
}
target "wincc-mock" {
  name       = "wincc-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/wincc-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/wincc-mock:${variant}"]
}
target "oracle-ebs-mock" {
  name       = "oracle-ebs-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/oracle-ebs-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/oracle-ebs-mock:${variant}"]
}
target "elite-bulletin-board-mock" {
  name       = "elite-bulletin-board-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/elite-bulletin-board-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/elite-bulletin-board-mock:${variant}"]
}
target "barracuda-mock" {
  name       = "barracuda-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/barracuda-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/barracuda-mock:${variant}"]
}
target "asustor-mock" {
  name       = "asustor-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/asustor-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/asustor-mock:${variant}"]
}
target "centreon-mock" {
  name       = "centreon-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/centreon-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/centreon-mock:${variant}"]
}
target "awstats-mock" {
  name       = "awstats-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/awstats-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/awstats-mock:${variant}"]
}
target "manageengine-5337-mock" {
  name       = "manageengine-5337-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/manageengine-5337-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/manageengine-5337-mock:${variant}"]
}
target "dolibarr-mock" {
  name       = "dolibarr-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/dolibarr-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/dolibarr-mock:${variant}"]
}
target "clipbucket-mock" {
  name       = "clipbucket-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/clipbucket-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/clipbucket-mock:${variant}"]
}
target "wp-symposium-mock" {
  name       = "wp-symposium-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/wp-symposium-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/wp-symposium-mock:${variant}"]
}
target "zabbix-mock" {
  name       = "zabbix-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/zabbix-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/zabbix-mock:${variant}"]
}
target "phprecipebook-mock" {
  name       = "phprecipebook-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/phprecipebook-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/phprecipebook-mock:${variant}"]
}

target "infusionsoft-gravityforms-mock" {
  name       = "infusionsoft-gravityforms-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/infusionsoft-gravityforms-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/infusionsoft-gravityforms-mock:${variant}"]
}
target "webjump-mock" {
  name       = "webjump-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/webjump-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/webjump-mock:${variant}"]
}

target "symantec-epm-mock" {
  name       = "symantec-epm-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/symantec-epm-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/symantec-epm-mock:${variant}"]
}
target "phplinkadmin-mock" {
  name       = "phplinkadmin-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/phplinkadmin-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/phplinkadmin-mock:${variant}"]
}
target "gravityboardx-mock" {
  name       = "gravityboardx-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/gravityboardx-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/gravityboardx-mock:${variant}"]
}
target "deluxebb-mock" {
  name       = "deluxebb-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/deluxebb-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/deluxebb-mock:${variant}"]
}
target "jobhut-mock" {
  name       = "jobhut-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/jobhut-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/jobhut-mock:${variant}"]
}
target "ajaxportal-mock" {
  name       = "ajaxportal-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/ajaxportal-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/ajaxportal-mock:${variant}"]
}

target "axis2-mock" {
  name       = "axis2-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/axis2-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/axis2-mock:${variant}"]
}
target "axis2-redirect-mock" {
  name       = "axis2-redirect-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/axis2-redirect-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/axis2-redirect-mock:${variant}"]
}
target "kloxo-mock" {
  name       = "kloxo-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/kloxo-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/kloxo-mock:${variant}"]
}
target "leaguemanager-mock" {
  name       = "leaguemanager-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/leaguemanager-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/leaguemanager-mock:${variant}"]
}
target "articlefr-mock" {
  name       = "articlefr-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/articlefr-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/articlefr-mock:${variant}"]
}
target "elearning-server-mock" {
  name       = "elearning-server-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/elearning-server-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/elearning-server-mock:${variant}"]
}
target "trombinoscope-mock" {
  name       = "trombinoscope-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/trombinoscope-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/trombinoscope-mock:${variant}"]
}
target "apprain-mock" {
  name       = "apprain-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/apprain-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/apprain-mock:${variant}"]
}
target "efront-mock" {
  name       = "efront-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/efront-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/efront-mock:${variant}"]
}
target "refbase-mock" {
  name       = "refbase-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/refbase-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/refbase-mock:${variant}"]
}
target "zerocms-mock" {
  name       = "zerocms-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/zerocms-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/zerocms-mock:${variant}"]
}
target "dokeos-mock" {
  name       = "dokeos-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/dokeos-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/dokeos-mock:${variant}"]
}
