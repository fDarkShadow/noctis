# Changelog

All notable changes to noctis are documented here.
## [0.3.0] — 2026-11-26

### Bug fixes

- **expr:** Keep stored-result objects intact across a script step (#393) (#453)
- **bake:** Restore 41 missing closing braces in misc.hcl (#689)
- **engine:** Interpolate http_request method; reject templates in literal step fields
- **mocks:** Jenkins-mock sends X-Jenkins and exposes /cli in vuln mode
- **infra:** Common_docker can test UDP mocks (target_protocol: udp)
- **infra:** Publish test mock ports on 127.0.0.1 only
- **infra:** Rename canon CVE-2018-12049 playbook so task test / test-all find it
- **scan:** Redact encoded credential forms; no secrets in test panics
- **engine:** Redact step errors; single-pass, hex-aware secret masking
- **general:** Reject echoed requests in SMB2 negotiate parse (#699 review)
- **CVE-2015-4107:** Version-gate the Wing FTP authenticated exec check
- **CVE-2015-4107:** Make patched mock differ only by version; login via /admin_loginok.html

### CI/CD

- Parse every infra/bake/*.hcl on pull requests (#690)
- Cancel superseded PR runs and deploy Pages only on release (#691)

### Dependencies

- **deps:** Bump crates, Rust 1.100 image and Pages actions

### Documentation

- Real vulnerability counts, generated; document the new layout
- **feeds:** Correct filter name exclude_categories; empty category regex
- Sync README, Pages and CONTRIBUTING with the current engine and tooling (#707)

### Features

- **engine:** Persistent multi-round-trip TCP socket + CVE-2022-24706 (#467)
- **CVE-2020-17496:** Add detection feed and test infrastructure (#480)
- **CVE-2025-13315:** Add detection feed and test infrastructure (#468)
- **CVE-2024-54767:** Add detection feed and test infrastructure (#469)
- **CVE-2018-1150:** Add detection feed and test infrastructure (#470)
- **CVE-2024-8956:** Add detection feed and test infrastructure (#472)
- **CVE-2021-33044:** Add detection feed and test infrastructure (#473)
- **CVE-2020-8656:** Add detection feed and test infrastructure (#474)
- **CVE-2025-34043:** Add detection feed and test infrastructure (#475)
- **CVE-2024-3721:** Add detection feed and test infrastructure (#476)
- **CVE-2018-19300:** Add detection feed and test infrastructure (#477)
- **CVE-2020-5847:** Add detection feed and test infrastructure (#478)
- **CVE-2021-20837:** Add detection feed and test infrastructure (#479)
- **CVE-2018-1000861:** Add Jenkins Stapler ACL bypass feed + test infra (#466)
- **CVE-2019-7609:** Add Kibana Timelion prototype-pollution RCE feed + test infra (#471)
- **CVE-2023-27351:** Add PaperCut NG/MF auth bypass feed + test infra (#481)
- **CVE-2025-32975:** Add Quest KACE SMA SSO auth bypass feed + test infra (#483)
- **CVE-2026-20230:** Add Cisco Unified CM WebDialer SSRF/RCE feed + test infra (#484)
- **CVE-2022-22963:** Add Spring Cloud Function SpEL RCE feed + test infra (#485)
- **CVE-2023-27482:** Add Home Assistant Supervisor auth bypass feed + test infra (#486)
- **CVE-2019-16662:** Add rConfig unauthenticated RCE feed + test infra (#487)
- **CVE-2026-48282:** Add ColdFusion RDS unauthenticated file write feed + test infra (#488)
- **CVE-2026-34910:** Add UniFi OS unauthenticated RCE chain feed + test infra (#482)
- **CVE-2011-5325:** NUUO NVRmini 2 — unauthenticated endpoint access detection (#592)
- **CVE-2018-11711:** Canon MF210/MF220 printers access bypass (#589)
- **CVE-2009-4883:** PHPRecipeBook <= 2.24 — unauthenticated SQL injection detection (#590)
- **CVE-2013-5743:** Add zabbix httpmon.php SQLi detection feed + test infra (#591)
- **CVE-2015-6522:** Wp-symposium — get_album_item.php SQL injection (#593)
- **clipbucket-multiple-vulns:** Add clipbucket videos.php SQLi detection feed + test infra (#594)
- **CVE-2011-3315:** Add cucm IVRGetAudioFile traversal detection feed + test infra (#595)
- **dolibarr-404-mult-vuln:** Add dolibarr SQL error (style.css.php lang) detection feed + test infra (#596)
- **manageengine-desktop-central-dbqueryexecutor:** Add manageengine Desktop Central DB Query Executor detection feed + test infra (#597)
- **CVE-2017-1000501:** Add awstats config traversal detection feed + test infra (#598)
- **CVE-2014-3828:** Centreon — displayServiceStatus.php SQL injection detection (#599)
- **CVE-2018-11509:** ASUSTOR ADM — unauthenticated RCE via aggrecate_js.cgi (#600)
- **CVE-2010-20109:** Barracuda Networks — view_help.cgi directory traversal (#601)
- **CVE-2012-5874:** Elite Bulletin Board — multiple SQL injection detection (#602)
- **CVE-2017-3549:** Oracle E-Business Suite — IESFOOTPRINT SQL injection detection (#603)
- **simatic-wincc-input-validation:** Siemens SIMATIC WinCC HMI — multiple input validation vulnerabilities (#604)
- **CVE-2013-4789:** Cotonti — 'c' parameter error-based SQL injection (#605)
- **CVE-2013-2248:** Apache Struts — S2-016/S2-017 DefaultActionMapper prefix injection (#606)
- **cups-webui-xss:** Add CUPS < 2.0.3 reflected XSS detection feed + test infra (#607)
- **netgear-readynas-cmd-injection:** NetGear ReadyNAS RAIDiator — FrontView unauthenticated command injection (#608)
- **CVE-2021-44736:** Lexmark Printer Configuration Wipe Vulnerability (#609)
- **CVE-2018-12049:** Canon-lbp6030w — auth bypass (#610)
- **CVE-2017-7588:** Brother — web authorization bypass (#611)
- **CVE-2016-4350:** Solarwinds-srm — SRM multiple SQL injection (#612)
- **CVE-2018-11692:** Canon — printer auth bypass (#613)
- **quantum-scalar-lfi:** Add Quantum Scalar i500 LFI detection feed + test infra (#614)
- **splunk-multiple-vuln:** Splunk 4.x — multiple web vulnerabilities active check (#615)
- **CVE-2016-6553:** Nuuo — NVR default credentials (#616)
- **CVE-2015-0930:** SerVision HVG Default Credentials (#617)
- **CVE-2014-9183:** Add detection feed and test infrastructure (#618)
- **CVE-2001-0320:** Add detection feed and test infrastructure (#619)
- **CVE-2013-1594:** Add detection feed and test infrastructure (#620)
- **CVE-2013-4775:** Add detection feed and test infrastructure (#621)
- **CVE-2013-2741:** Add detection feed and test infrastructure (#623)
- **CVE-2004-1647:** Password Protect SQLi Vulnerability (#624)
- **CVE-2004-1719:** Add detection feed and test infrastructure (#625)
- **CVE-2017-8835:** Add detection feed and test infrastructure (#626)
- **CVE-2016-5817:** Add detection feed and test infrastructure (#627)
- **CVE-2016-6195:** Add detection feed and test infrastructure (#628)
- **CVE-2015-4654:** Joomla! EQ Event Calendar component SQL Injection Vulnerability (#629)
- **CVE-2015-5148:** Add detection feed and test infrastructure (#630)
- **CVE-2015-2825:** WordPress Simple Ads Manager Plugin File Upload Vulnerability (#631)
- **CVE-2015-1471:** Add detection feed and test infrastructure (#632)
- **CVE-2015-7297:** Add detection feed and test infrastructure (#633)
- **CVE-2013-5957:** Civicrm — unauthenticated SQL injection detection (#634)
- **CVE-2014-3437:** Add detection feed and test infrastructure (#635)
- **CVE-2014-4511:** Gitlist RCE Vulnerability (#636)
- **CVE-2014-6446:** WordPress Infusionsoft Gravity Forms Add-on Arbitrary File Upload Vuln (#638)
- **CVE-2009-4892:** WEBJump! — unauthenticated SQL injection detection (#639)
- **CVE-2015-0975:** Opennms — default credentials rtc/rtc login flow (#640)
- **CVE-2013-5014:** Symantec-epm — SEPM XXE & SQL injection (#641)
- **CVE-2009-1024:** Beerwin's PhpLinkAdmin — unauthenticated SQL injection detection (#642)
- **CVE-2014-8295:** Bacula-web — jobid SQL injection feed + test infra (#643)
- **CVE-2009-1277:** Gravity Board X — unauthenticated SQL injection detection (#644)
- **CVE-2009-1033:** DeluxeBB — unauthenticated SQL injection detection (#645)
- **CVE-2012-5357:** Ektron — Ektron CMS < 8.02 SP5 RCE (#646)
- **CVE-2009-4797:** JobHut — unauthenticated SQL injection detection (#647)
- **CVE-2009-1509:** MyioSoft Ajax Portal — unauthenticated SQL injection detection (#648)
- **CVE-2010-0219:** Axis2 — Apache Axis2 default credentials (#649)
- **CVE-2014-4852:** Atomcms — AtomCMS SQLi / file upload (#650)
- **CVE-2013-1965:** Struts — S2-012 Showcase OGNL RCE (#651)
- **CVE-2009-3099:** Tomcat-admin — default admin credentials (#652)
- **CVE-2014-125124:** Kloxo — unauthenticated SQL injection detection (#653)
- **CVE-2014-1206:** Open-web-analytics — password-reset SQLi (#654)
- **CVE-2013-1852:** Leaguemanager — unauthenticated export/SQL injection detection (#655)
- **CVE-2008-6270:** Apoll — admin/login.php SQL injection (#656)
- **CVE-2014-125115:** Pandora — FMS < 5.1 SP1 multiple vulns (#657)
- **CVE-2018-11523:** Nuuo-nvrmini2 — file upload RCE (#658)
- **CVE-2024-50630:** Synology — BeeStation SA-24:21 webapi info disclosure (#659)
- **CVE-2007-6369:** Wordpress — multiple plugins/themes directory traversal / file download (#660)
- **CVE-2014-5097:** ArticleFR CMS — unauthenticated SQL injection detection (#661)
- **CVE-2012-2923:** ELearning Server 4G — unauthenticated SQL injection detection (#662)
- **CVE-2012-5849:** ClipBucket — unauthenticated SQL injection detection (#663)
- **CVE-2021-27850:** Apache Tapestry 5.4.0<5.6.3/5.7.0<5.7.1 — RCE exposure detection (#664)
- **CVE-2012-4282:** Trombinoscope — unauthenticated SQL injection detection (#665)
- **CVE-2017-8860:** Cohu 3960HD cameras — directory listing exposure detection (#666)
- **CVE-2017-3184:** ACTi cameras — factory-default page auth-bypass detection (#667)
- **CVE-2011-5228:** AppRain CMF — unauthenticated SQL injection detection (#668)
- **CVE-2016-5639:** Crestron AirMedia AM-100 — unauthenticated file read detection (#669)
- **CVE-2013-3316:** NETGEAR WNR1000v3 — config request auth-bypass detection (#670)
- **CVE-2010-1918:** EFront — unauthenticated SQL injection detection (#671)
- **CVE-2013-10043:** Astium VoIP PBX ≤2.1 — SQLi login-bypass detection (#672)
- **CVE-2013-0632:** Adobe ColdFusion — admin authentication bypass detection (#673)
- **CVE-2012-5692:** Invision Power Board — PHP code execution exposure detection (#674)
- **CVE-2010-4278:** Pandora FMS ≤3.1 — authentication bypass detection (#675)
- **CVE-2016-6277:** NETGEAR routers — unauthenticated command injection detection (#676)
- **CVE-2015-6007:** Refbase — unauthenticated SQL injection detection (#677)
- **CVE-2021-21816:** D-Link DIR-3040 — unauthenticated syslog disclosure detection (#678)
- **CVE-2020-25078:** D-Link DCS IP cameras — credential disclosure detection (#679)
- **CVE-2015-7765:** ManageEngine OpManager ≤11.6 — default-account detection (#680)
- **CVE-2013-5709:** Siemens Scalance X-200 — config file disclosure detection (#681)
- **CVE-2025-34126:** RIPS Scanner 0.55 — local file inclusion detection (#683)
- **CVE-2012-5687:** TP-LINK TL-WR841N — unauthenticated file read detection (#684)
- **CVE-2018-17786:** D-Link / TOTOLINK ExportSettings.sh — broken access control detection (#685)
- **CVE-2017-8917:** Joomla! <3.7.1 — SQLi login-page fingerprint detection (#686)
- **CVE-2014-4034:** ZeroCMS — unauthenticated SQL injection detection (#687)
- **CVE-2013-6341:** Dokeos — unauthenticated SQL injection detection (#622)
- **CVE-2010-4970:** Wiki Web Help — unauthenticated SQL injection detection (#637)
- **CVE-2013-1627:** Add Advantech Studio NTWebServer traversal detection feed + test infra (#688)
- **scan:** Credentials surface for authenticated scans (#693)
- **CVE-2015-4107:** Add Wing FTP Server admin default account feed + test infrastructure
- **CVE-2015-4107:** Rework Wing FTP feed into faithful authenticated check (#693)
- **general:** SMB2 negotiate probe — signing not required (#354)
- **CVE-2015-4107:** Wing FTP Server ≤4.3.8 — authenticated admin Lua command execution (#701)
- **CVE-2024-21182:** Oracle WebLogic Server T3/IIOP data disclosure — version detection
- **CVE-2026-28318:** Serv-U deflate DoS — FTP banner version check (#702)
- **CVE-2026-48558:** SimpleHelp RMM — OIDC authentication bypass (#703)
- **CVE-2021-31805:** Apache Struts2 S2-062 — forced double OGNL evaluation RCE (#704)
- **beestation-sa-24-23:** Synology BeeStation (BSM) SA-24:23 webapi file disclosure (#705)

### Refactoring

- **feeds:** One directory per product, common http_base include
- **mocks:** Shared Python base image, generated bake file, no dead mocks
- **mocks:** Move advantech-mock (from #688) onto py-mock-base

### Tests

- **CVE-2024-21182:** Add unaffected-version TN host and 14.1.1.0.0 https twin; reject unknown mock mode

## [0.2.1] — 2026-11-23

### CI/CD

- **docker:** Drop cargo-chef, cache dependencies with a stub main.rs (#434)
- Multi-arch :edge via a reusable image workflow shared with the release (#435)
- **image:** Publish OCI metadata so the GHCR package page renders docs (#451)

### Documentation

- Set up GitHub Discussions (category forms + routing) (#436)

### Refactoring

- **loader:** Replace deprecated serde_yaml with serde-saphyr (#449)
- **time:** Replace unmaintained chrono with jiff (#450)

### Security

- **deps:** Fix RUSTSEC-2026-0592 (url), fold in dependabot bumps, document audit exceptions (#446)

## [0.2.0] — 2026-11-21

### Bug fixes

- **pages:** Centre the final call-to-action paragraph (#430)
- **feeds:** Restore the HTTP security-headers check (broken include path) (#432)

### CI/CD

- **release:** Build amd64 and arm64 in parallel on native runners (#424)
- **release:** Fail the release if the tag doesn't match Cargo.toml (#425)

### Documentation

- Overhaul README (TOC, structure) and document new engine actions (#426)
- **pages:** Full-width marketing landing page for the Pages site (#428)
- **pages:** Migrate the whole site to the new design, drop just-the-docs (#429)

### Features

- **docker:** Bundle the detection feeds in the image, overridable by mount (#431)

## [0.1.0] — 2026-11-20

### Bug fixes

- **agent-loop:** Guard resume check against already-completed issues
- **infra:** Fix loop index and evidence serialization in findings detail
- **CVE-2024-0012:** Create panos-ztp-mock for ZTP auth bypass detection
- **infra:** Restart noctis on crash, add health check before each scan
- **oob:** Resolve all OOB callback failures in test suite
- **agents:** Replace --reviewer with --assignee in make-test PR creation
- **ci:** Switch lint/test to ubuntu-latest, apply cargo fmt
- **ci:** Correct yaml-schema binary name (ys) and CLI syntax
- **ci+deps:** Fix audit job permissions, cache binaries, patch vulns
- **feeds:** Add services field to misconfig feeds, fix http_base port
- **ci:** Lowercase GHCR image name to satisfy Docker tag requirements
- **docker:** Eliminate double dep compilation in cargo-chef setup
- **ci:** Add apt-get update before libssh2-1-dev install
- **mocks:** Stop ivanti-epm-mock and roundcube-mock from overwriting sibling CVE detections
- **lint:** Clippy needless_bool in ScanFilters::excludes (Rust 1.100)
- **favicon:** Transparent corners instead of white (#421)

### CI/CD

- Add CI/CD workflows, Dependabot and Dockerfile ssh2 fix
- Update GitHub Actions to latest major versions
- **codeql:** Fail job when findings are detected
- **codeql:** Replace autobuild with explicit cargo build
- **codeql:** Annotate PR diff with findings via workflow commands
- **codeql:** Remove useless cargo build — Rust extractor is build-less
- **codeql:** Suppress known false positives via query-filters config
- Switch Docker cache backend from GHA to registry
- Multi-arch (arm64) release image + document Docker/GHCR usage (#419)

### Documentation

- **agents:** Propagate branch coverage expectations through fill-backlog→make-test
- Add CI, license and Docker image badges to README
- Add CHANGELOG.md generated by git-cliff
- Add SECURITY.md with vulnerability disclosure policy
- Add Code of Conduct, Contributing guide, and PR templates (#417)
- SEO/discoverability — README Why/Use-cases, CITATION.cff, Pages site (#418)

### Features

- **CVE-2023-34362:** Add detection feed and test infrastructure
- **CVE-2024-3400:** Add detection feed and test infrastructure
- **CVE-2023-4966:** Add detection feed and test infrastructure
- **CVE-2023-20198:** Add detection feed and test infrastructure
- **CVE-2024-45519:** Add detection feed and test infrastructure
- **CVE-2023-46604:** Add detection feed and test infrastructure
- **CVE-2024-4040:** Add detection feed and test infrastructure
- **CVE-2022-47966:** Add detection feed and test infrastructure
- **CVE-2023-22515:** Add detection feed and test infrastructure
- **CVE-2021-42013:** Add detection feed and test infrastructure
- **infra:** Replace Ansible image builds with docker buildx bake
- **infra:** REST API testing, playbook auto-discovery, task cleanup
- **infra:** Containerize noctis, parallelize mock builds, update docs
- **docker:** Switch noctis image to Alpine musl + scratch runtime
- **CVE-2024-38856:** Add Apache OFBiz detection feed and test infrastructure
- **CVE-2023-26360:** Add Adobe ColdFusion file read detection feed and test infrastructure
- **CVE-2024-29824:** Add Ivanti EPM SOAP SQLi detection feed and test infrastructure
- **CVE-2024-28986:** SolarWinds WHD — version-based Java deserialization detection
- **CVE-2024-5217:** Add ServiceNow Jelly file read via SecurelyAccess detection
- **CVE-2024-4879:** Add ServiceNow Jelly SSTI pre-auth RCE detection
- **CVE-2025-49113:** Add Roundcube Webmail deserialization RCE version detection
- **CVE-2026-34197:** Add Apache ActiveMQ Jolokia unauthenticated RCE detection
- **CVE-2026-3055:** Add Citrix NetScaler SAML IDP memory overread detection
- **CVE-2026-1603:** Add Ivanti EPM auth bypass via logintype=64 detection
- **CVE-2026-0257:** Add PAN-OS GlobalProtect auth bypass detection
- **CVE-2026-21643:** Add FortiClientEMS time-based SQLi via Site header detection
- **CVE-2026-41940:** Add cPanel WHM CRLF session injection detection
- **CVE-2025-54068:** Add Laravel Livewire v3 deserialization RCE detection
- **CVE-2026-10520:** Ivanti Sentry MICS API — unauthenticated OS command injection
- **CVE-2024-27199:** JetBrains TeamCity — path traversal auth bypass detection
- **CVE-2024-55956:** Cleo Harmony — VSYNC identity probe + OOB Autorun RCE
- **CVE-2023-2868:** Barracuda ESG — firmware version detection for TAR RCE
- **CVE-2025-31324:** Add SAP NetWeaver Visual Composer file upload RCE detection
- **CVE-2023-50164:** Add detection feed and test infrastructure
- **CVE-2019-0708:** Add detection feed and test infrastructure
- **CVE-2021-26084:** Add detection feed and test infrastructure
- **CVE-2024-6670:** Add detection feed and test infrastructure
- **CVE-2021-26086:** Add detection feed and test infrastructure
- **CVE-2024-40711:** Add detection feed and test infrastructure
- **CVE-2024-53704:** Add SonicWall SSL VPN session hijacking detection
- **CVE-2024-4885:** Add Progress WhatsUp Gold SSRF detection via SOAP OOB callback
- **CVE-2024-28995:** Add SolarWinds Serv-U directory traversal file read detection
- **CVE-2024-1212:** Add Progress Kemp LoadMaster OS command injection detection
- **CVE-2023-43770:** Add detection feed and test infrastructure
- **CVE-2025-31161:** Add detection feed and test infrastructure
- **CVE-2025-3248:** Add detection feed and test infrastructure
- **CVE-2024-27348:** Add Apache HugeGraph-Server Gremlin API RCE detection
- **CVE-2024-41713:** Add detection feed and test infrastructure
- **CVE-2025-0282:** Add detection feed and test infrastructure
- **CVE-2024-56145:** Add detection feed and test infrastructure
- **CVE-2025-34028:** Add Commvault Command Center pre-auth SSRF detection
- **CVE-2024-11680:** ProjectSend CSRF bypass via unauthenticated options.php POST
- **CVE-2024-48248:** NAKIVO Backup & Replication arbitrary file read detection
- **CVE-2024-7593:** Add Ivanti vTM auth bypass detection feed and test infrastructure
- **CVE-2026-23760:** Add detection feed and test infrastructure
- **CVE-2024-50603:** Add detection feed and test infrastructure
- **CVE-2024-9465:** Add detection feed and test infrastructure
- **CVE-2021-41277:** Add detection feed and test infrastructure
- **CVE-2024-20439:** Add detection feed and test infrastructure
- **CVE-2024-28987:** Add SolarWinds WHD hardcoded credential detection
- **CVE-2024-38475:** Add SonicWall SMA100 mod_rewrite bypass detection
- **CVE-2024-57727:** Add SimpleHelp path traversal detection
- **CVE-2024-34102:** Add Magento CosmicSting XXE/SSRF detection
- **CVE-2025-26399:** Add SolarWinds WHD AjaxProxy deserialization detection
- **CVE-2025-32433:** Add Erlang/OTP SSH version fingerprint detection
- **CVE-2023-47218:** Add QNAP QTS unauthenticated command injection detection
- **CVE-2025-23006:** Add SonicWall SMA1000 AMC version fingerprint detection
- **CVE-2019-9621:** Add Zimbra ZCS Autodiscover XXE LFI detection feed and test infrastructure
- **CVE-2021-22175:** Add GitLab CI Lint SSRF OOB detection feed and test infrastructure
- **CVE-2026-20253:** Add Splunk PostgreSQL sidecar pre-auth detection feed and test infrastructure
- **CVE-2025-61757:** Add Oracle Identity Manager auth bypass detection feed and test infrastructure
- **CVE-2026-35273:** Add Oracle PeopleSoft SSRF OOB detection feed and test infrastructure
- **CVE-2025-2747:** Add Kentico Xperience SOAP staging auth bypass detection
- **CVE-2024-5910:** Add Palo Alto Expedition unauthenticated admin reset detection
- **CVE-2025-25257:** Add Fortinet FortiWeb SQL injection via Bearer header detection
- **CVE-2021-20123:** Add DrayTek VigorConnect unauthenticated LFI detection
- **CVE-2024-32113:** Add Apache OFBiz Groovy RCE via ProgramExport path traversal
- **CVE-2025-34026:** Add Versa Concerto actuator auth bypass detection
- **CVE-2024-58136:** Add Yii2 PHP Framework RCE via __class deserialization detection
- **CVE-2024-51567:** Add CyberPanel pre-auth OS command injection detection
- **CVE-2025-4427:** Add Ivanti EPMM SSTI RCE detection (auth bypass + code injection)
- **CVE-2024-45195:** Add Apache OFBiz xmldsdump direct request RCE detection
- **CVE-2025-24893:** Add XWiki SolrSearch Groovy RCE detection
- **CVE-2025-0108:** Add PAN-OS management interface auth bypass detection
- **CVE-2022-43769:** Add Pentaho BA Server SpEL injection detection
- **CVE-2023-35082:** Ivanti EPMM unauthenticated admin API access
- **CVE-2023-23752:** Joomla! unauthenticated REST API config credential disclosure
- **CVE-2023-43208:** Mirth Connect pre-auth deserialization RCE + OOB
- **CVE-2025-52691:** SmarterMail unauthenticated file upload path traversal
- **CVE-2022-43939:** Pentaho BA Server auth bypass via non-canonical URL
- **CVE-2024-7399:** Samsung MagicINFO 9 path traversal file write RCE
- **CVE-2024-12356:** Add BeyondTrust PRA/RS command injection RCE detection
- **CVE-2025-68613:** Add n8n expression injection RCE version fingerprint detection
- **CVE-2025-20281:** Add Cisco ISE unauthenticated Java deserialization RCE detection
- **CVE-2025-48703:** Add CWP Control Web Panel unauthenticated RCE detection
- **CVE-2025-5777:** Add Citrix NetScaler CitrixBleed 2 memory disclosure detection
- **CVE-2025-30406:** Add Gladinet CentreStack machineKey deserialization detection
- **automation:** Add CVE backlog + PR review pipeline (Phases 0-3)
- **CVE-2019-15107:** Add Webmin password_change.cgi RCE feed + mock
- **CVE-2019-15107:** Add Webmin password_change.cgi RCE feed + mock
- **engine:** String/regex/byte builtins for feed expressions
- **engine:** Ssh_exec action — credential check + command output
- **engine:** Snmp_get action (v2c) via the csnmp crate
- **engine:** Tcp_dialogue action — line protocols (FTP/SMTP/Telnet/POP3/IMAP)
- **engine:** Tcp_syn action — raw SYN half-open port probe (pnet)
- **engine:** Udp_probe action — generic UDP request/response
- **engine:** Crypto/encoding builtins (hashes, HMAC, base64)
- **ftp-anonymous:** Anonymous-FTP check via tcp_dialogue + schema fix
- **smtp-open-relay:** SMTP open-relay check via tcp_dialogue
- **snmp-default-community:** SNMP default-community check + fix IPv4 bind
- **memcached-udp-exposed:** Memcached UDP exposure check via udp_probe
- **ssh-default-credentials:** SSH default-creds check via ssh_exec
- **redis-unauthenticated:** Redis unauth-access check via tcp_dialogue
- **dns-open-resolver:** Open recursive DNS resolver check via udp_probe
- **ntp-monlist:** NTP monlist amplification check (CVE-2013-5211) via udp_probe
- **feeds:** Detect unauthenticated Elasticsearch exposure
- **feeds:** Flag exposed cleartext Telnet service
- **feeds:** Flag POP3/IMAP cleartext authentication
- **engine+feeds:** Binary tcp_dialogue probe + MongoDB unauth check
- **engine:** Misc builtins — sleep step, rand_*, pack/unpack
- **feeds:** Flag VNC servers with no authentication
- **feeds:** Flag LDAP anonymous bind
- **feeds:** Flag SMBv1 enabled (legacy protocol exposed)
- **feeds:** Flag rsync anonymous module listing
- **feeds:** Flag ZooKeeper 4lw admin commands exposed
- **feeds:** Flag Memcached exposed over TCP without auth
- **feeds:** Flag finger service user disclosure
- **feeds:** Flag PostgreSQL passwordless (trust) access
- **feeds:** Flag MQTT brokers accepting anonymous connections
- **feeds:** Flag CouchDB admin-party (unauthenticated)
- **feeds:** Flag etcd exposed without authentication
- **feeds:** Flag Docker Engine API exposed without auth
- **feeds:** Flag Kubernetes API anonymous access
- **feeds:** Flag Cassandra CQL accessible without auth
- **feeds:** Flag open X11 display (no authentication)
- **feeds:** Flag Jenkins anonymous read access
- **feeds:** Flag Prometheus exposed without authentication
- **feeds:** Flag Apache Spark master exposed without auth
- **feeds:** Flag Jupyter with authentication disabled
- **feeds:** Flag Hadoop YARN ResourceManager exposed without auth
- **feeds:** Flag Consul HTTP API exposed without ACLs

### Refactoring

- **infra:** Replace docker buildx bake with podman build
- **tests:** Model vulnerabilities as 0..N CVEs, organize by vendor, add integrity tooling

### Tests

- **infra:** Assert CVE ID, confidence, and QoD per detection branch
- **infra:** Add OOB test hosts for all wait_oob feeds, fix expected_qod


