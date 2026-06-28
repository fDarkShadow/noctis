target "apache-cve-2021-41773" {
  name       = "apache-cve-2021-41773-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/apache-cve-2021-41773"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/apache-cve-2021-41773:${variant}"]
}

target "apache-cve-2021-42013" {
  name       = "apache-cve-2021-42013-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/apache-cve-2021-42013"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/apache-cve-2021-42013:${variant}"]
}

target "apache-mod-proxy-mock" {
  name       = "apache-mod-proxy-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/apache-mod-proxy-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/apache-mod-proxy-mock:${variant}"]
}
