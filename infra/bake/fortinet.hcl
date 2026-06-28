target "forticlientems-mock" {
  name       = "forticlientems-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/forticlientems-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/forticlientems-mock:${variant}"]
}

target "fortigate-mock" {
  name       = "fortigate-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/fortigate-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/fortigate-mock:${variant}"]
}

target "fortimanager-mock" {
  name       = "fortimanager-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/fortimanager-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/fortimanager-mock:${variant}"]
}

target "fortios-ssl-vpn-mock" {
  name       = "fortios-ssl-vpn-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/fortios-ssl-vpn-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/fortios-ssl-vpn-mock:${variant}"]
}
