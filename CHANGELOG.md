# Changelog

All notable changes to noctis are documented here.
## [Unreleased]

### Bug fixes

- **agent-loop:** Guard resume check against already-completed issues
- **infra:** Fix loop index and evidence serialization in findings detail
- **CVE-2024-0012:** Create panos-ztp-mock for ZTP auth bypass detection
- **infra:** Restart noctis on crash, add health check before each scan
- **oob:** Resolve all OOB callback failures in test suite
- **agents:** Replace --reviewer with --assignee in make-test PR creation

### CI/CD

- Add CI/CD workflows, Dependabot and Dockerfile ssh2 fix

### Documentation

- **agent-loop:** Add Step 0 (read CLAUDE.md) + enrich CLAUDE.md for agents
- **readme:** Rewrite for GitHub — exhaustive and clean
- **agents:** Propagate branch coverage expectations through fill-backlog→make-test
- Add CI, license and Docker image badges to README

### Features

- **CVE-2024-6387:** Add OpenSSH regreSSHion detection feed
- **CVE-2023-49103:** Add ownCloud graphapi phpinfo disclosure detection
- **CVE-2024-4577:** Add detection feed and test infrastructure
- **CVE-2024-21887:** Add detection feed and test infrastructure
- **CVE-2023-46805:** Add detection feed and test infrastructure
- **CVE-2022-22965:** Add detection feed and test infrastructure
- **CVE-2021-43798:** Add detection feed and test infrastructure
- **CVE-2023-22527:** Add detection feed and test infrastructure
- **CVE-2024-21893:** Add Ivanti SAML SSRF detection feed and test infrastructure
- **CVE-2026-9082:** Add Drupal anonymous SQL injection detection feed and test infrastructure
- **CVE-2021-22205:** Add GitLab ExifTool RCE detection feed and test infrastructure
- **agent-loop:** Assign fDarkShadow as reviewer on PR creation
- **CVE-2023-7028:** Add detection feed and test infrastructure
- **CVE-2021-21985:** Add detection feed and test infrastructure
- **agent-loop:** Add context-loss recovery (Step 1)
- **CVE-2023-34960:** Add detection feed and test infrastructure
- **CVE-2024-55591:** Add detection feed and test infrastructure
- **CVE-2017-1000353:** Add detection feed and test infrastructure
- **CVE-2024-27198:** Add detection feed and test infrastructure
- **CVE-2023-34362:** Add detection feed and test infrastructure
- **CVE-2024-3400:** Add detection feed and test infrastructure
- **CVE-2023-4966:** Add detection feed and test infrastructure
- **CVE-2023-20198:** Add detection feed and test infrastructure
- **CVE-2024-45519:** Add detection feed and test infrastructure
- **CVE-2023-42793:** Add detection feed and test infrastructure
- **CVE-2024-0012:** Add detection feed and test infrastructure
- **CVE-2025-24813:** Add detection feed and test infrastructure
- **CVE-2025-1974:** Add detection feed and test infrastructure
- **CVE-2024-9463:** Add detection feed and test infrastructure
- **CVE-2022-22954:** Add detection feed and test infrastructure
- **CVE-2021-40438:** Add detection feed and test infrastructure
- **CVE-2024-21762:** Add detection feed and test infrastructure
- **CVE-2023-41266:** Add detection feed and test infrastructure
- **CVE-2024-24919:** Add detection feed and test infrastructure
- **CVE-2024-8963:** Add detection feed and test infrastructure
- **CVE-2024-4358:** Add detection feed and test infrastructure
- **CVE-2024-20767:** Add detection feed and test infrastructure
- **CVE-2024-23692:** Add detection feed and test infrastructure
- **CVE-2024-36401:** Add detection feed and test infrastructure
- **CVE-2024-47575:** Add detection feed and test infrastructure
- **CVE-2025-22457:** Add detection feed and test infrastructure
- **CVE-2025-32432:** Add detection feed and test infrastructure
- **CVE-2024-50623:** Add detection feed and test infrastructure
- **CVE-2023-48788:** Add detection feed and test infrastructure
- **CVE-2024-53677:** Add detection feed and test infrastructure
- **CVE-2024-1709:** Add detection feed and test infrastructure
- **CVE-2021-22986:** Add detection feed and test infrastructure
- **CVE-2022-46169:** Add detection feed and test infrastructure
- **CVE-2023-22518:** Add detection feed and test infrastructure
- **CVE-2023-46747:** Add detection feed and test infrastructure
- **CVE-2023-46604:** Add detection feed and test infrastructure
- **CVE-2024-4040:** Add detection feed and test infrastructure
- **CVE-2022-47966:** Add detection feed and test infrastructure
- **CVE-2023-22515:** Add detection feed and test infrastructure
- **CVE-2021-42013:** Add detection feed and test infrastructure
- **CVE-2023-28432:** Add detection feed and test infrastructure
- **CVE-2024-23897:** Add detection feed and test infrastructure
- **CVE-2024-0204:** Add detection feed and test infrastructure
- **CVE-2023-27524:** Add detection feed and test infrastructure
- **CVE-2025-29927:** Add detection feed and test infrastructure
- **infra:** Replace Ansible image builds with docker buildx bake
- **infra:** REST API testing, playbook auto-discovery, task cleanup
- **infra:** Containerize noctis, parallelize mock builds, update docs
- **docker:** Switch noctis image to Alpine musl + scratch runtime
- **CVE-2024-38856:** Add Apache OFBiz detection feed and test infrastructure
- **CVE-2023-26360:** Add Adobe ColdFusion file read detection feed and test infrastructure

### Refactoring

- **infra:** Replace docker buildx bake with podman build

### Tests

- **infra:** Assert CVE ID, confidence, and QoD per detection branch
- **infra:** Add OOB test hosts for all wait_oob feeds, fix expected_qod


