## Update - Issue #34914

### Scope covered
- Evaluated and implemented changes for:
  - `.github/workflows/5_testintegration_fim-tier-0-1-win.yml`
  - `.github/workflows/5_testintegration_fim-tier-2-win.yml` (evaluation pending final decision)
  - `.github/workflows/5_builderpackage_agent-windows.yml` (artifact-reuse evaluation)

### Implemented
- **Tier 0-1 workflow parallelization** implemented in `.github/workflows/5_testintegration_fim-tier-0-1-win.yml`.
- The `run-test` job was split into a **2-shard matrix**:
  - `tier-0` → `pytest --tier 0`
  - `tier-1` → `pytest --tier 1`
- Added a **single package job** that builds the MSI once and shares it across both shards.
- Kept the package handoff **inside the same workflow run**, so the test shards install the artifact built from that exact execution.
- Resolved the MSI name from `VERSION.json` before packaging, removing the dependency on the placeholder `wazuh-agent--.msi` path.
- Updated failed-results artifact naming to include shard and avoid collisions.

### Baseline evidence (before changes)
Source details: `comments/34914.md`

#### Tier 0-1 (5 recent successful runs)
- Mean total duration: **102.21 min**
- Median total duration: **99.93 min**
- p95 total duration: **111.58 min**
- Failure rate (sample): **0%**

#### Tier 2 (available runs are sparse)
- Current sample is insufficiently stable/representative for a hard optimization decision without additional controlled runs.

### After-change validation (pending run completion)
Once new runs finish, fill with outputs from:
- `python3 comments/collect_34914_metrics.py --workflow 5_testintegration_fim-tier-0-1-win.yml --branch enhancement/34914-fim-win-parallelization --limit 5`
- (Optional tier-2 test branch):
  `python3 comments/collect_34914_metrics.py --workflow 5_testintegration_fim-tier-2-win.yml --branch enhancement/34914-fim-win-parallelization --limit 5`

### Artifact reuse from builder workflow
**Status: Under evaluation.**

Initial assessment:
- Cross-workflow artifact reuse introduces higher coupling (run-id/commit selection, retention, permissions, race conditions).
- Adoption should be conditioned on measurable wall-clock gains that clearly offset this complexity.

### Provisional decision
- **Tier 0-1 parallelization:** Implemented, pending runtime confirmation from post-change runs.
- **Tier 2 parallelization:** Pending additional measurements.
- **Builder artifact reuse:** Pending; the workflow already avoids rebuilding the MSI per shard, so cross-workflow reuse should only be added if it shows a clear extra gain.

### Trade-offs
- Expected lower wall-clock execution time for tier 0-1.
- Increased concurrent runner usage and slightly higher workflow complexity.
- Risk managed by packaging once per workflow run and using a simple tier-based split for the test stage.
