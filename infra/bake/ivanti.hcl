target "ivanti-mock" {
  name       = "ivanti-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/ivanti-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/ivanti-mock:${variant}"]
}

target "ivanti-csa-mock" {
  name       = "ivanti-csa-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/ivanti-csa-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/ivanti-csa-mock:${variant}"]
}

target "ivanti-ics-mock" {
  name       = "ivanti-ics-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/ivanti-ics-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/ivanti-ics-mock:${variant}"]
}

target "ivanti-rce-mock" {
  name       = "ivanti-rce-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/ivanti-rce-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/ivanti-rce-mock:${variant}"]
}

target "ivanti-saml-mock" {
  name       = "ivanti-saml-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/ivanti-saml-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/ivanti-saml-mock:${variant}"]
}
