target "php-cgi-mock" {
  name       = "php-cgi-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/php-cgi-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/php-cgi-mock:${variant}"]
}

target "shellshock-mock" {
  name       = "shellshock-mock-${variant}"
  matrix     = { variant = ["vuln", "patched"] }
  context    = "../docker/shellshock-mock"
  dockerfile = "Dockerfile.${variant}"
  tags       = ["noctis/shellshock-mock:${variant}"]
}

# phpunit uses separate directories (one Dockerfile each)
target "phpunit-vuln" {
  context    = "../docker/phpunit-vuln"
  dockerfile = "Dockerfile"
  tags       = ["noctis/phpunit-vuln:local"]
}

target "phpunit-patched" {
  context    = "../docker/phpunit-patched"
  dockerfile = "Dockerfile"
  tags       = ["noctis/phpunit-patched:local"]
}
