target "confluence-mock" {
  name       = "confluence-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/confluence-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/confluence-mock:${variant}"]
}

target "confluence-restore-mock" {
  name       = "confluence-restore-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/confluence-restore-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/confluence-restore-mock:${variant}"]
}

target "confluence-setup-mock" {
  name       = "confluence-setup-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/confluence-setup-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/confluence-setup-mock:${variant}"]
}

target "confluence-ssti-mock" {
  name       = "confluence-ssti-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/confluence-ssti-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/confluence-ssti-mock:${variant}"]
}
