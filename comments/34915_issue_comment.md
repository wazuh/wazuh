## Update - Issue #34915

### Scope covered
- Evaluated and implemented changes for:
  - `.github/workflows/5_testintegration_fim-tier-0-1-lin.yml`
  - `.github/workflows/5_testintegration_fim-tier-2-lin.yml` (evaluation pending final decision)
  - `.github/workflows/5_builderpackage_agent-linux.yml` (artifact-reuse evaluation)

### Implemented
- **Tier 0-1 workflow parallelization** implemented in `.github/workflows/5_testintegration_fim-tier-0-1-lin.yml`.
- The `build` job was split into a **2-shard matrix**:
  - `tier-0` → `pytest --tier 0`
  - `tier-1` → `pytest --tier 1`
- Updated failed-results artifact naming to include shard and avoid collisions.

> **Architecture note:** The Linux FIM workflow uses a single combined job (build + install + test). Unlike the Windows counterpart, there is no separate build/run-test split, so each shard currently runs the full build cycle. A future optimization (artifact reuse) could eliminate this duplication.

### Baseline evidence (before changes)
Source details: `comments/34915.md`

#### Tier 0-1 (5 recent successful runs)
- Mean total duration: **139.15 min**
- Median total duration: **138.22 min**
- p95 total duration: **144.90 min**
- Failure rate (sample): **0%**

#### Tier 2 (available runs are sparse)
- Only 2 successful runs found (mean 78.98 min, p95 89.92 min).
- Current sample is insufficiently stable/representative for a hard optimization decision without additional controlled runs.

### After-change validation (pending run completion)
Once new runs finish, fill with outputs from:
- `python3 comments/collect_34915_metrics.py --workflow 5_testintegration_fim-tier-0-1-lin.yml --branch enhancement/34915-fim-lin-parallelization --limit 5`
- (Optional tier-2 test branch):
  `python3 comments/collect_34915_metrics.py --workflow 5_testintegration_fim-tier-2-lin.yml --branch enhancement/34915-fim-lin-parallelization --limit 5`

### Artifact reuse from builder workflow
**Status: Under evaluation.**

Initial assessment:
- Cross-workflow artifact reuse introduces higher coupling (run-id/commit selection, retention, permissions, race conditions).
- For Linux this has **higher potential impact** than Windows: each shard currently recompiles the full agent. If the artifact from `5_builderpackage_agent-linux.yml` were reused, both shards would skip the build phase entirely.
- Adoption should be conditioned on measurable wall-clock gains that clearly offset this complexity.

### Provisional decision
- **Tier 0-1 parallelization:** Implemented, pending runtime confirmation from post-change runs.
- **Tier 2 parallelization:** Pending additional measurements.
- **Builder artifact reuse:** Pending; higher priority than Windows given the double-build overhead introduced by the matrix.

### Trade-offs
- Expected lower wall-clock execution time for tier 0-1.
- Each shard performs a full rebuild until artifact reuse is resolved (double build cost per workflow run).
- Increased concurrent runner usage and slightly higher workflow complexity.
- Risk managed by keeping the split simple (tier-based) and using `fail-fast: false`.
