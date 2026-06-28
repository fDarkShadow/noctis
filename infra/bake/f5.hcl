target "bigip-mock" {
  name       = "bigip-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/bigip-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/bigip-mock:${variant}"]
}

target "bigip-22986-mock" {
  name       = "bigip-22986-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/bigip-22986-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/bigip-22986-mock:${variant}"]
}

target "bigip-46747-mock" {
  name       = "bigip-46747-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/bigip-46747-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/bigip-46747-mock:${variant}"]
}
