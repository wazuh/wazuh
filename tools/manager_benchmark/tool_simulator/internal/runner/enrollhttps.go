package runner

import (
	"context"
	"errors"
	"fmt"

	"github.com/wazuh/wazuh/tools/manager_benchmark/tool_simulator/internal/enrollhttps"
	"github.com/wazuh/wazuh/tools/manager_benchmark/tool_simulator/internal/wire"
)

// enrollHTTPSVersion is the version the enrolled names claim when the fleet's
// metadata does not say (the manager refuses a version newer than its own
// unless allow_higher_versions is set).
const enrollHTTPSVersion = "5.0.0"

// prepareEnrollToken resolves the enrollment token an `enroll_https` step
// presents, BEFORE any traffic: a scenario that carries such a step and no
// token is a setup error, not a run that measures less. The token is
// environment config like the cluster name -- it is a credential the operator
// minted on the manager under test -- so it never lives in the scenario file
// (see docu/16-enroll-https.md); it reaches the sender through
// --enroll-token-file or WAZUH_ENROLLMENT_TOKEN. Scenarios without the step
// need nothing.
func (r *Runner) prepareEnrollToken() error {
	needed := false
	for _, steps := range r.scn.Lanes {
		for _, step := range steps {
			if step.Kind == "enroll_https" {
				needed = true
			}
		}
	}
	if !needed {
		return nil
	}
	if r.cfg.EnrollToken == "" {
		return errors.New("the scenario has enroll_https steps but no enrollment token was given: pass " +
			"--enroll-token-file <file> or set WAZUH_ENROLLMENT_TOKEN (mint one on the manager with " +
			"`wazuh-manager-authd --create-enrollment-token --address <manager>`)")
	}
	token, err := wire.ParseEnrollmentToken(r.cfg.EnrollToken)
	if err != nil {
		return err
	}
	r.enrollToken = token
	r.enrollKey = token.Key()
	return nil
}

// runEnrollHTTPS sends one POST /enroll with the enrollment-token bearer, for a
// NEW agent name derived from this agent's own (`<name>-tk-<n>`, keeping the
// `bench-` prefix cleanup_agents.sh keys on). The identity the answer mints is
// recorded and dropped: the step measures the path, it does not adopt the
// result -- this simulated agent keeps running under the identity it got from
// the 1515 bootstrap.
func (a *agent) runEnrollHTTPS(ctx context.Context, lane string) {
	if a.enroll == nil || a.r.enrollToken == nil {
		// prepareEnrollToken() runs before any agent does, so this is a programming error, not
		// a run condition.
		a.r.fatalf("agent %s enroll_https: no enrollment token client (scenario validated without one?)", a.id)
		return
	}
	if err := a.r.sessionLimiter.Wait(ctx); err != nil {
		return
	}

	name := fmt.Sprintf("%s-tk-%d", a.name, a.enrollSeq.Add(1))
	version := a.fleet.Start.AgentVersion
	if version == "" {
		version = enrollHTTPSVersion
	}

	a.r.requestStarted()
	res, err := enrollhttps.Request(a.enroll, a.r.enrollKey, a.r.enrollToken.ID, name, version, now())
	a.r.requestFinished()

	if err != nil {
		// A protocol error still produced a real answer, so record it and then
		// invalidate the run: a 200 without the agent record, or a status the
		// contract does not name, means the sender is not talking to remoted's
		// /enroll the way it thinks (docu/10).
		if perr, ok := err.(*enrollhttps.ErrProtocol); ok {
			a.r.reg.RecordEnrollHTTPS(a.fleet.Name, lane, res.Status, us(res.Latency))
			a.r.fatalf("agent %s enroll_https: %v", a.id, perr)
			return
		}
		a.r.reg.RecordTransportError(a.fleet.Name, lane)
		return
	}

	// 401/403/409 are the manager's contract outcomes, recorded as such; a
	// scenario's `expected` block decides whether they are acceptable for the run.
	a.r.reg.RecordEnrollHTTPS(a.fleet.Name, lane, res.Status, us(res.Latency))
}
