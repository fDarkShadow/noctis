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
