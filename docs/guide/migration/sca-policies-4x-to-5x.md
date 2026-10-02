# SCA policies from 4.x to 5.x

This guide describes the manual changes required to run custom Security Configuration Assessment (SCA) policies created for Wazuh 4.x on Wazuh 5.x.

There is no automatic migration tool for custom SCA policies. Review each custom policy, migrate it to the 5.x policy format, and validate it on a non-production 5.x agent before rolling it out.

For the current custom policy schema, see [Creating custom SCA policies](../../ref/modules/sca/custom-policies.md).

## Summary of changes

| Area | 4.x behavior | 5.x behavior | Migration action |
|---|---|---|---|
| Regular expression engine | `osregex` was the default SCA regex engine. Policies and checks could set `regex_type`. | All SCA rules are evaluated with PCRE2. The `regex_type` field is ignored: the engine is always PCRE2 and OSRegex is no longer available. | Rewrite every `r:` and `n:` expression that depends on OSRegex syntax so it is valid PCRE2. The now-ignored `regex_type` field can be removed. |
| Policy and check names | Requirements and checks used `title`. | `name` is the canonical field; stock policies, runtime state, and generated events use `name`. A `title` field is still accepted and automatically mapped to `name`, but is deprecated. | Rename `requirements.title` and each `checks[*].title` to `name`. The rename is recommended rather than mandatory, since legacy `title` is still mapped to `name`. |
| Compliance metadata | Many stock policies used an array of single-key objects, often with versioned keys such as `pci_dss_v4.0`. | `compliance` is an object. Only normalized keys are accepted: `cmmc`, `fedramp`, `gdpr`, `hipaa`, `iso_27001`, `nis2`, `nist_800_171`, `nist_800_53`, `pci_dss`, and `tsc`. | Convert the array format to an object and use only supported keys. An unsupported key is dropped with an `Invalid compliance key` warning; a `compliance` that is not an object (the 4.x array) is dropped whole with an `Unexpected compliance format` warning. |
| MITRE metadata | MITRE values were commonly stored under compliance keys such as `mitre_tactics`, `mitre_techniques`, and `mitre_mitigations`. | MITRE data is stored in a separate `mitre` object with the keys `tactic`, `technique`, and `subtechnique`, each an object holding parallel `id` and `name` arrays. | Move MITRE values out of `compliance` and into `mitre`, as `id`/`name` arrays. A key whose value is not an object (for example a plain array of IDs) is dropped from the check's results without a warning. |
| Numeric comparisons | Some stock 4.x rules used forms such as `compare =`, `compare =>`, `compare =<`, missing spaces, or an escaped `\!=`. | Numeric expressions require `compare <`, `compare <=`, `compare ==`, `compare !=`, `compare >=`, or `compare >` followed by a value. Spaces are required around `compare` and the operator. | Normalize every `n:` expression and make sure the regex captures the numeric value in a group. |
| SCA configuration | Some 4.x configurations included `<skip_nfs>`. | `<skip_nfs>` is deprecated for SCA and is logged at INFO level as no longer available. SCA synchronization settings are available under `<synchronization>`. | Remove `<skip_nfs>` from SCA configuration. Keep or tune synchronization settings as needed. |
| Stock policies | Stock policy files under `ruleset/sca` were package-managed. | Upgrades replace stock policies. Some legacy stock policies were removed, including HP-UX, RHEL 5, SLES/SUSE 11, and Solaris/SunOS policies. | Do not customize files under `ruleset/sca`. Keep custom policies in a separate managed path and reference them explicitly. |

## Step-by-step migration

1. Inventory all custom SCA policies currently in use.

   Include policies referenced from `<sca><policies>` and any policy copied into a shared agent group. Check both local agent policies and manager-distributed policies.

   Watch for `<policy>` entries that reference legacy filenames ending in `_rcl.yml`, such as `cis_rhel7_linux_rcl.yml`, `system_audit_rcl.yml`, or `win_audit_rcl.yml`. These are old policy names carried over from earlier Wazuh versions, not 5.x SCA policy files. The SCA configuration reader keeps a built-in list of these filenames and silently skips them, without logging a warning, if they are still referenced in `<sca><policies>`, so remove or replace those references. Note that only the exact filenames in that built-in list are skipped silently; any other missing or unresolved policy path instead logs a `File '...' not found.` warning when the configuration is read, or `Policy file does not exist: ...` when the module loads its policies.

2. Back up policies and move custom files out of package-managed paths.

   Do not edit or store custom policies in `$WAZUH_HOME/ruleset/sca`. Package upgrades replace stock policy files in that directory. Use an administrator-managed path and point `<policy>` entries to that path.

   Policies under `$WAZUH_HOME/etc/shared` are shared policies. The agent treats a policy as remote when its `<policy>` entry is declared in the shared `agent.conf` and its resolved path is not inside the package-managed `$WAZUH_HOME/ruleset/sca` directory. Command rules (`c:`) in remote policies run only when the `sca.remote_commands` internal option is enabled. The check depends on where the entry is declared, not on the path string: a policy under `etc/shared/` is normally declared through the shared `agent.conf`, so it is remote, while an external path such as `/opt/wazuh-sca/custom_linux.yml` is local when declared in the agent's own configuration and remote when declared in the shared `agent.conf`. An external path must exist locally on each agent.

   ```xml
   <sca>
     <enabled>yes</enabled>
     <scan_on_start>yes</scan_on_start>
     <interval>12h</interval>
     <policies>
       <!-- Shared policy: distributed through etc/shared; when declared in the shared agent.conf, command rules require sca.remote_commands=1. -->
       <policy>etc/shared/default/sca/custom_linux.yml</policy>
       <!-- External local policy: must exist on each agent. -->
       <policy>/opt/wazuh-sca/custom_linux_local.yml</policy>
       <policy enabled="no">ruleset/sca/cis_debian12.yml</policy>
     </policies>
     <synchronization>
       <enabled>yes</enabled>
       <interval>5m</interval>
       <integrity_interval>24h</integrity_interval>
       <max_eps>75</max_eps>
     </synchronization>
   </sca>
   ```

3. Rename `title` fields to `name`.

   `name` is the canonical field. For backward compatibility, a `title` field is still accepted and automatically mapped to `name`, so existing 4.x policies keep working; however, `title` is deprecated. Rename it in `requirements` and in every check:

   ```yaml
   requirements:
     name: "Run only on Linux hosts"

   checks:
     - id: 90001
       name: "Ensure SSH root login is disabled"
   ```

4. Convert SCA rules to PCRE2.

   The `regex_type` field is ignored in 5.x (the engine is always PCRE2), so it can be removed. Because every pattern is now evaluated as PCRE2, review every rule that uses `r:` or `n:`. The following changes are required, because the original pattern either fails to compile under PCRE2 or no longer evaluates correctly:

   | 4.x pattern | 5.x pattern | Reason |
   |---|---|---|
   | `r:*` | `r:\*` | A bare `*` is a quantifier with nothing to repeat and fails PCRE2 compilation; escape it to match a literal `*`. |
   | `n:audit_backlog_limit=(d+) compare >= 8192` | `n:audit_backlog_limit=(\d+) compare >= 8192` | Use the `\d` digit class so the capture group matches the numeric value. |
   | `n:remember=(\d+) compare => 5` | `n:remember=(\d+) compare >= 5` | `=`, `=>`, and `=<` are not valid operators; use `==`, `>=`, and `<=`. |
   | `n:gpgcheck=(\d+) compare \!= 1` | `n:gpgcheck=(\d+) compare != 1` | Do not escape comparison operators. |

   Also replace OSRegex-specific wildcards such as `\p` with an explicit PCRE2 character class that matches the intended data. For example, if the policy needs one of `*`, `!`, `+`, or `-`, use `[*!+-]`.

   The following patterns still compile under PCRE2 but change meaning, so rewrite them only when the original intent requires it:

   | 4.x pattern | PCRE2 rewrite | When to apply |
   |---|---|---|
   | `r:pam_unix.so`, `r:127.0.0.1` | `r:pam_unix\.so`, `r:127\.0\.0\.1` | `.` matches any character in PCRE2. Escape the dots if they must match literal dots only. |
   | `r:\.+`, `r:\.*.conf` | `r:.+`, `r:.*\.conf` | `\.` is a literal dot in PCRE2. If the intent was "any character", use `.`. |
   | `r:\w+` | `r:[\w@-]+` | `\w+` is valid as-is; widen the class only if matched values can contain characters such as `@` or `-`. |

5. Convert compliance and MITRE metadata.

   Use only supported compliance keys and move MITRE values to the `mitre` object, giving each ID its ATT&CK name at the same position:

   ```yaml
   compliance:
     pci_dss: ["2.2"]
     nist_800_53: ["CM-6"]
     tsc: ["CC6.6"]
   mitre:
     tactic:
       id: ["TA0005"]
       name: ["Defense Evasion"]
     technique:
       id: ["T1036"]
       name: ["Masquerading"]
   ```

   See [MITRE keys](../../ref/modules/sca/custom-policies.md#mitre-keys) in the custom policy reference.

6. Remove deprecated SCA configuration.

   Delete `<skip_nfs>` from the SCA module configuration. If you explicitly configure synchronization, keep it under `<synchronization>` as shown in step 2.

7. Validate the migrated policy on Wazuh 5.x.

   Install the policy on a non-production 5.x agent (SCA runs on agents only: a 5.x manager has no SCA module), restart the agent, and run a scan. Check the Wazuh logs for policy parsing, invalid compliance keys, and PCRE2 errors. Search for messages such as `Failed to parse policy`, `Invalid compliance key`, `Unexpected compliance format`, and `PCRE2 compilation failed`.

8. Roll out incrementally.

   Start with one agent group or one endpoint type. Compare SCA results with the expected 4.x behavior, then expand deployment once the migrated policies parse cleanly and produce the expected pass, fail, and not applicable results.

## Migration example

The following 4.x check uses `title`, OSRegex syntax, array-style compliance metadata, MITRE values inside `compliance`, and a reversed numeric comparison operator:

```yaml
policy:
  id: "custom_linux"
  file: "custom_linux.yml"
  name: "Custom Linux hardening"
  description: "Custom checks for Linux endpoints."
  regex_type: "osregex"

requirements:
  title: "Run only on Linux hosts"
  description: "Linux host requirement."
  condition: all
  rules:
    - "f:/proc/sys/kernel/ostype -> Linux"

checks:
  - id: 90001
    title: "Check SSH and password aging"
    compliance:
      - pci_dss_v4.0: ["2.2.6"]
      - nist_sp_800-53: ["CM-6"]
      - mitre_tactics: ["TA0005"]
      - mitre_techniques: ["T1036"]
    condition: all
    rules:
      - 'f:/etc/pam.d/system-auth -> r:pam_unix.so && n:remember=(\d+) compare => 5'
      - 'not f:/etc/shadow -> n:^\w+:\$\.*:\d+:\d+:(\d+): compare > 365'
```

The 5.x version uses `name`, drops the now-ignored `regex_type` field, converts compliance and MITRE metadata, and rewrites the expressions for PCRE2:

```yaml
policy:
  id: "custom_linux"
  file: "custom_linux.yml"
  name: "Custom Linux hardening"
  description: "Custom checks for Linux endpoints."

requirements:
  name: "Run only on Linux hosts"
  description: "Linux host requirement."
  condition: all
  rules:
    - "f:/proc/sys/kernel/ostype -> Linux"

checks:
  - id: 90001
    name: "Check SSH and password aging"
    compliance:
      pci_dss: ["2.2.6"]
      nist_800_53: ["CM-6"]
    mitre:
      tactic:
        id: ["TA0005"]
        name: ["Defense Evasion"]
      technique:
        id: ["T1036"]
        name: ["Masquerading"]
    condition: all
    rules:
      - 'f:/etc/pam.d/system-auth -> r:pam_unix\.so && n:remember=(\d+) compare >= 5'
      - 'not f:/etc/shadow -> n:^[\w@-]+:\$.*:\d+:\d+:(\d+) compare > 365'
```

## Final checklist

- Custom policies are stored outside `$WAZUH_HOME/ruleset/sca`.
- SCA configuration references the migrated custom policy paths.
- `requirements` and checks use `name` (the deprecated `title` still works but should be replaced).
- The `regex_type` field is removed (it is ignored in 5.x; all patterns are PCRE2).
- All regex and numeric expressions compile as PCRE2.
- `compliance` is an object with supported keys only.
- MITRE metadata is under `mitre`, as `id`/`name` arrays per category.
- `<skip_nfs>` is removed from SCA configuration.
- A non-production 5.x validation scan completes without SCA parsing or PCRE2 errors.
