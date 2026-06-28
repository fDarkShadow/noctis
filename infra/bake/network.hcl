target "checkpoint-mock" {
  name       = "checkpoint-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/checkpoint-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/checkpoint-mock:${variant}"]
}

target "cisco-wsma-mock" {
  name       = "cisco-wsma-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/cisco-wsma-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/cisco-wsma-mock:${variant}"]
}

target "expedition-mock" {
  name       = "expedition-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/expedition-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/expedition-mock:${variant}"]
}

target "netscaler-mock" {
  name       = "netscaler-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/netscaler-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/netscaler-mock:${variant}"]
}

target "panos-mock" {
  name       = "panos-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/panos-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/panos-mock:${variant}"]
}

target "panos-ztp-mock" {
  name       = "panos-ztp-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/panos-ztp-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/panos-ztp-mock:${variant}"]
}

target "qlik-sense-mock" {
  name       = "qlik-sense-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/qlik-sense-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/qlik-sense-mock:${variant}"]
}

target "workspace-one-mock" {
  name       = "workspace-one-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/workspace-one-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/workspace-one-mock:${variant}"]
}
