# Migrating from CIS-CAT and OpenSCAP to SCA

In previous Wazuh versions (4.x), configuration and policy assessment could be performed with two integration wodles configured in the agent's `ossec.conf`: CIS-CAT (`<wodle name="cis-cat">`), which ran the external CIS-CAT Assessor against CIS benchmark content, and OpenSCAP (`<wodle name="open-scap">`), which ran the external OpenSCAP scanner against SCAP content (XCCDF profiles and OVAL definitions).

Starting with Wazuh 5.0, both wodles have been **removed**. The agent no longer ships the CIS-CAT or OpenSCAP integrations, and no module is registered under those names. Configuration assessment is now performed natively by the **Security Configuration Assessment (SCA)** module, which evaluates the system against YAML policies bundled with the agent — no Java runtime, no external CIS-CAT Assessor, and no `openscap-scanner` package are required.

> **Note:** If a `<wodle name="cis-cat">` or `<wodle name="open-scap">` block is left in `ossec.conf` (or in a shared `agent.conf`) after upgrading to 5.0, the block is ignored and the agent logs an informational message: `INFO: The 'cis-cat' module is deprecated. Use the SCA module instead.` or `INFO: The 'open-scap' module is deprecated. Use the SCA module instead.` The configuration still loads and the agent starts, but the wodles no longer run, so remove these blocks as part of the migration.

> **Note:** There is no automatic tool to convert XCCDF, SCAP, or OVAL content into SCA policies. The CIS benchmarks you previously assessed with CIS-CAT or OpenSCAP are, in most cases, already covered by the SCA policies bundled under `ruleset/sca`. Custom XCCDF content must be re-authored as SCA YAML policies, and OVAL/CVE content is handled by a different module — see the mapping below.

## Capability mapping (4.x -> 5.x)

The following table maps each CIS-CAT and OpenSCAP capability from Wazuh 4.x to its Wazuh 5.x equivalent.

| Capability                  | CIS-CAT / OpenSCAP (4.x)                                       | Wazuh 5.x equivalent                                                                 |
| --------------------------- | ------------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| Configuration block         | `<wodle name="cis-cat">` / `<wodle name="open-scap">`         | [`<sca>`](../../ref/modules/sca/configuration.md)                                    |
| Policy/benchmark format     | XCCDF / SCAP datastream                                       | YAML policy file                                                                     |
| External dependency         | Java runtime + CIS-CAT Assessor / `openscap-scanner`          | None — assessment is built into the agent                                            |
| CIS benchmark content       | Benchmark files downloaded and referenced by path             | Bundled policies under `ruleset/sca` (per distribution and version)                  |
| Custom benchmark content    | Custom XCCDF profile                                          | [Custom SCA YAML policy](../../ref/modules/sca/custom-policies.md)                   |
| Compliance scan results     | Alerts + agent database                                       | SCA events sent to the indexer; SCA inventory in the Wazuh dashboard                 |
| Vulnerability (OVAL) scan   | OpenSCAP OVAL content (e.g. `cve-redhat-7-ds.xml`)            | [Vulnerability Detection module](../../ref/modules/vulnerability-scanner/README.md) — **not** SCA |

> **Important:** SCA replaces the **configuration-assessment** (XCCDF) side of CIS-CAT and OpenSCAP only. The **vulnerability-assessment** (OVAL/CVE) side of OpenSCAP has no SCA equivalent. In Wazuh, CVE detection is a separate capability (Vulnerability Detector in 4.x, the [Vulnerability Detection module](../../ref/modules/vulnerability-scanner/README.md) in 5.x). If your OpenSCAP configuration included `<content type="oval">` blocks, do not expect SCA to reproduce them — enable Vulnerability Detection instead.

## Wazuh 4.x ossec.conf reference

Below are the typical Wazuh 4.x wodle blocks you may have in your `ossec.conf`. Use them as a reference when following the migration steps.

```xml
<!-- Wazuh 4.x ossec.conf -->

<!-- CIS-CAT: runs the external CIS-CAT Assessor against a CIS benchmark profile -->
<wodle name="cis-cat">
  <disabled>no</disabled>
  <timeout>1800</timeout>
  <interval>1d</interval>
  <scan-on-start>yes</scan-on-start>
  <java_path>wodles/java</java_path>
  <ciscat_path>wodles/ciscat</ciscat_path>
  <content type="xccdf" path="benchmarks">
    <profile>xccdf_org.cisecurity.benchmarks_profile_Level_1_-_Server</profile>
  </content>
</wodle>

<!-- OpenSCAP: runs the external scanner against XCCDF (compliance) and OVAL (vulnerability) content -->
<wodle name="open-scap">
  <disabled>no</disabled>
  <timeout>1800</timeout>
  <interval>1d</interval>
  <scan-on-start>yes</scan-on-start>
  <content type="xccdf" path="ssg-centos-7-ds.xml">
    <profile>xccdf_org.ssgproject.content_profile_pci-dss</profile>
  </content>
  <content type="oval" path="cve-redhat-7-ds.xml"/>
</wodle>
```

## Migration steps

### Prerequisites

Before proceeding, make sure you have:

- Wazuh 5.0 or later deployed (indexer, manager, dashboard) and the agents upgraded.
- Access to each agent's local `ossec.conf`, and to the Wazuh manager, where shared `agent.conf` files are edited (one per agent group, under `etc/shared/<group>/`) before being pushed to agents.
- A list of the benchmarks and profiles you previously assessed with CIS-CAT and OpenSCAP, so you can match them to the equivalent SCA policies.

> These steps remove the deprecated wodles and replace them with SCA. Apply them wherever the wodles were configured: in each agent's local `ossec.conf`, and in any shared `agent.conf` on the manager.

## 1. Inventory your CIS-CAT and OpenSCAP configuration

Locate every `<wodle name="cis-cat">` and `<wodle name="open-scap">` block. Check the local `ossec.conf` on each agent **and** the shared `agent.conf` of each agent group on the manager (under `etc/shared/<group>/agent.conf`), since a single shared configuration is distributed to every agent in the group and can carry the deprecated wodles to many agents at once.

For each block, note the benchmark content and profile it referenced (the `<content>` `path` and `<profile>` values). You will use this to select the matching SCA policy in [Step 3](#3-map-your-benchmarks-to-sca-policies). For OpenSCAP, record any `<content type="oval">` entries separately — those map to Vulnerability Detection ([Step 6](#6-move-ovalcve-scanning-to-vulnerability-detection-openscap-only)), not SCA.

## 2. Remove the cis-cat and open-scap wodle blocks

Delete the `<wodle name="cis-cat">` and `<wodle name="open-scap">` blocks. Edit the local `ossec.conf` directly on each agent, and edit any shared `agent.conf` on the manager (in the group's `etc/shared/<group>/` directory) — not on the agents, which receive that file from the manager.

Wazuh 5.0 no longer registers a runnable module under either name: leftover blocks are ignored with an INFO deprecation message and provide no assessment, so remove them to keep the configuration clean.

## 3. Map your benchmarks to SCA policies

Wazuh ships SCA policies for common CIS benchmarks under `ruleset/sca`, organized by distribution and version — for example `ruleset/sca/centos/7/cis_centos7_linux.yml`, `ruleset/sca/rhel/7/cis_rhel7_linux.yml`, or `ruleset/sca/ubuntu/cis_ubuntu24-04.yml`. In most cases the CIS benchmark you assessed with CIS-CAT or the SSG XCCDF profile you assessed with OpenSCAP already has a bundled SCA policy equivalent.

Identify the SCA policy that corresponds to each benchmark you recorded in [Step 1](#1-inventory-your-cis-cat-and-openscap-configuration). SCA auto-loads the policies bundled for the detected platform; you can also enable specific policies explicitly in the next step. See the [SCA module overview](../../ref/modules/sca/README.md) and the [SCA configuration reference](../../ref/modules/sca/configuration.md) for the available options.

## 4. Enable and configure SCA

Add or update the `<sca>` block in `ossec.conf`. SCA is enabled by default and auto-loads the bundled policies for the platform; the `<policies>` section lets you enable specific policies explicitly or disable ones you do not need.

```xml
<sca>
  <enabled>yes</enabled>
  <scan_on_start>yes</scan_on_start>
  <interval>1d</interval>
  <policies>
    <policy>ruleset/sca/centos/7/cis_centos7_linux.yml</policy>
  </policies>
</sca>
```

The `<interval>` and `<scan_on_start>` options play the same role they did in the CIS-CAT and OpenSCAP wodles. See the [SCA configuration reference](../../ref/modules/sca/configuration.md) for all available options, including the `<synchronization>` settings.

## 5. Re-create custom benchmarks as SCA policies (if needed)

If you maintained **custom** XCCDF content — a tailored CIS profile or a hand-written SCAP benchmark with no bundled SCA equivalent — you must re-author it as a custom SCA YAML policy. There is no automatic XCCDF-to-SCA converter.

Follow [Creating custom SCA policies](../../ref/modules/sca/custom-policies.md) for the policy file format (sections, checks, rule types, compliance, and MITRE mapping). Store custom policies in an administrator-managed path — not under `ruleset/sca`, whose contents are replaced on package upgrades — and reference them with explicit `<policy>` entries.

If you are also bringing forward custom SCA policies that were written for Wazuh 4.x, review the [SCA policies from 4.x to 5.x](sca-policies-4x-to-5x.md) migration guide for the policy-format changes between versions.

## 6. Move OVAL/CVE scanning to Vulnerability Detection (OpenSCAP only)

If your OpenSCAP configuration included `<content type="oval">` blocks for CVE scanning (for example `cve-redhat-7-ds.xml`), that workload is **not** covered by SCA. Enable the [Vulnerability Detection module](../../ref/modules/vulnerability-scanner/README.md) instead, which detects CVEs by correlating the inventory collected by Syscollector against Wazuh's CVE databases. No OVAL content files are needed.

## 7. Apply the configuration

Restart the agent to apply the changes:

```bash
# Linux
systemctl restart wazuh-agent
```

If the deprecated wodles were distributed through a shared `agent.conf`, push the updated shared configuration from the manager and let it propagate to the assigned agents.

## 8. Validate the migration

Confirm that the migration succeeded on a representative agent:

1. Check the agent log (`/var/ossec/logs/ossec.log`) and verify there are **no** `The 'cis-cat' module is deprecated` or `The 'open-scap' module is deprecated` messages, which would indicate a leftover wodle block.
2. Confirm SCA runs. The log shows the scan boundaries:

   ```
   INFO: Scan started.
   ...
   INFO: Scan ended.
   ```

3. Review the results in the Wazuh dashboard SCA inventory, or query them through the API. See the [SCA output samples](../../ref/modules/sca/output-samples.md) and the [SCA database schema](../../ref/modules/sca/database-schema.md) for the data SCA produces.

<details>
<summary>Example A: rewriting a single OpenSCAP XCCDF rule as an SCA check</summary>

When you need to migrate a specific check rather than a whole policy, map the XCCDF rule to an equivalent SCA check. Take the **Install AIDE** rule from the SSG Ubuntu CIS profile, which verifies that the AIDE file-integrity package is installed. In XCCDF, the rule declares its identity and metadata and delegates the actual test to an OVAL definition that queries the package database:

```xml
<!-- OpenSCAP / SSG XCCDF rule -->
<Rule id="xccdf_org.ssgproject.content_rule_package_aide_installed" selected="true">
  <title>Install AIDE</title>
  <description>The aide package must be installed if it is to be available for integrity checking.</description>
  <reference href="https://www.cisecurity.org/benchmark/ubuntu_linux/">1.3.1</reference>
  <!-- The pass/fail logic lives in a separate OVAL definition that checks
       whether the 'aide' package is installed. -->
  <check system="http://oval.mitre.org/XMLSchema/oval-definitions-5">
    <check-content-ref href="ssg-ubuntu2204-oval.xml"
                       name="oval:ssg-package_aide_installed:def:1"/>
  </check>
</Rule>
```

In SCA, the rule's metadata and its test live together in one self-contained YAML check. The OVAL "is the package installed" test becomes a command rule that inspects the package database directly. This is exactly how the bundled Ubuntu CIS policy expresses it (`ruleset/sca/ubuntu/cis_ubuntu22-04.yml`):

```yaml
# SCA check
- id: 28526
  name: "Ensure AIDE is installed."
  description: "AIDE takes a snapshot of filesystem state including modification times, permissions, and file hashes which can then be used to compare against the current state of the filesystem to detect modifications to the system."
  rationale: "By monitoring the filesystem state compromised files can be detected to prevent or limit the exposure of accidental or malicious misconfigurations or modified binaries."
  remediation: "Install AIDE using the appropriate package manager or manual installation: # apt install aide aide-common"
  compliance:
    nist_800_53: ["AC-6"]
    pci_dss: ["10.2", "11.5"]
    # ... additional compliance keys omitted for brevity
  condition: all
  rules:
    - "c:dpkg-query -s aide -> r:Status: install ok installed"
    - "c:dpkg-query -s aide-common -> r:Status: install ok installed"
```

The mapping is direct: the XCCDF `title` becomes the SCA `name`, the `description`/rationale carry over, the CIS `reference` becomes entries under `compliance`, and the OVAL package test becomes the `c:` command rules under `rules`, combined with `condition: all`. Because this benchmark already ships with the agent, you would not normally rewrite it by hand — but the same pattern applies when migrating a **custom** XCCDF rule that has no bundled SCA equivalent. See [Creating custom SCA policies](../../ref/modules/sca/custom-policies.md) for the full rule syntax (rule types, content matching, compliance, and MITRE keys).

</details>

<details>
<summary>Example B: matching a CIS-CAT finding to an SCA check</summary>

CIS-CAT differs from OpenSCAP here: the CIS-CAT Pro Assessor and its machine-readable benchmark content (the automated XCCDF build) are proprietary and distributed only to CIS SecureSuite members, so there is no open XCCDF rule to copy from. What *is* public is the **CIS Benchmark recommendation** — its number, title, rationale, and audit/remediation text — published in the freely available CIS Benchmark PDF. That recommendation is also what a CIS-CAT scan reports as a finding.

So instead of rewriting a rule, you match the recommendation. Take the recommendation a CIS-CAT scan reported as a finding:

```
# CIS-CAT finding (as reported in a Wazuh 4.x alert)
Benchmark: CIS Ubuntu Linux 22.04 LTS Benchmark
Recommendation: 2.4.1.2 Ensure permissions on /etc/crontab are configured
Result: fail
```

Wazuh's bundled SCA CIS policies already implement these recommendations and preserve the CIS numbering in a comment, so the equivalent check is a direct lookup (`ruleset/sca/ubuntu/cis_ubuntu22-04.yml`):

```yaml
  # 2.4.1.2 Ensure permissions on /etc/crontab are configured. (Automated)
  - id: 28626
    name: "Ensure permissions on /etc/crontab are configured."
    description: "The /etc/crontab file is used by cron to control its own jobs. The commands in this item make sure that root is the user and group owner of the file and that only the owner can access the file."
    rationale: "This file contains information on what system jobs are run by cron. Write access to these files could provide unprivileged users with the ability to elevate their privileges."
    remediation: "Run the following commands to set ownership and permissions on /etc/crontab: # chown root:root /etc/crontab # chmod og-rwx /etc/crontab."
    compliance:
      nist_800_53: ["AC-5", "AC-6"]
      pci_dss: ["7.1", "1.3"]
      # ... additional compliance keys omitted for brevity
    condition: all
    rules:
      - 'c:stat -Lc "%n %a %u %U %g %G" /etc/crontab -> r:0 root 0 root && r:600'
```

Because the standard CIS benchmarks ship with the agent, migrating CIS-CAT is mostly an exercise in confirming that each recommendation you assessed maps to a bundled SCA check — usually no rewriting is required. The exception is a **tailored** CIS-CAT profile (custom recommendation selection or modified expected values). In that case, re-author the affected recommendations as SCA checks using the public CIS Benchmark PDF as the source of truth — do not copy CIS's proprietary automated content. See [Creating custom SCA policies](../../ref/modules/sca/custom-policies.md) for the rule syntax.

</details>

Once the deprecated wodles are removed, SCA is configured, and (for OpenSCAP) Vulnerability Detection is enabled, you have migrated your configuration and vulnerability assessment off CIS-CAT and OpenSCAP.
