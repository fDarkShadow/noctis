target "jenkins-mock" {
  name       = "jenkins-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/jenkins-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/jenkins-mock:${variant}"]
}

target "jenkins-cli-mock" {
  name       = "jenkins-cli-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/jenkins-cli-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/jenkins-cli-mock:${variant}"]
}

target "teamcity-mock" {
  name       = "teamcity-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/teamcity-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/teamcity-mock:${variant}"]
}

target "teamcity-token-mock" {
  name       = "teamcity-token-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/teamcity-token-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/teamcity-token-mock:${variant}"]
}
