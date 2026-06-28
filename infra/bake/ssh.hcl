# openssh: single Dockerfile per version, used as base for CVE-2023-48795 and CVE-2024-6387
target "openssh-9-5" {
  context    = "../docker/openssh-9.5"
  dockerfile = "Dockerfile"
  tags       = ["noctis/openssh:9.5"]
}

target "openssh-9-6" {
  context    = "../docker/openssh-9.6"
  dockerfile = "Dockerfile"
  tags       = ["noctis/openssh:9.6"]
}

target "ssh-terrapin-mock" {
  name       = "ssh-terrapin-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/ssh-terrapin-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/ssh-terrapin-mock:${variant}"]
}

target "regresshion-mock" {
  name       = "regresshion-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/regresshion-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/regresshion-mock:${variant}"]
}
