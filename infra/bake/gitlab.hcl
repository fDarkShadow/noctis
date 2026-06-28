target "gitlab-mock" {
  name       = "gitlab-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/gitlab-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/gitlab-mock:${variant}"]
}

target "gitlab-password-reset-mock" {
  name       = "gitlab-password-reset-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/gitlab-password-reset-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/gitlab-password-reset-mock:${variant}"]
}
