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

// prepareEnrollToken resolves the run's enrollment token, BEFORE any traffic: a
// run that needs one and has none is a setup error, not a run that measures
// less. Two things need it -- the fleet's bootstrap (`--bootstrap enroll-token`,
// the default) and an `enroll_https` step -- and the message says which, because
// the fixes differ (`--bootstrap 1515` is an answer to the first only).
//
// The token is environment config like the cluster name -- a credential the
// operator minted on the manager under test -- so it never lives in the scenario
// file (see docu/16-enroll-https.md); it reaches the sender through
// --enroll-token-file or WAZUH_ENROLLMENT_TOKEN.
func (r *Runner) prepareEnrollToken() error {
	var need string
	switch {
	case r.mode == "agent" && r.cfg.Bootstrap == BootstrapEnrollToken:
		need = "the fleet bootstraps over POST /enroll (--bootstrap enroll-token)"
	case r.hasEnrollHTTPSStep():
		need = "the scenario has enroll_https steps"
	default:
		return nil
	}
	if r.cfg.EnrollToken == "" {
		return fmt.Errorf("%s but no enrollment token was given: pass --enroll-token-file <file> or set "+
			"WAZUH_ENROLLMENT_TOKEN (mint one on the manager with `wazuh-manager-authd "+
			"--create-enrollment-token --address <manager>`, or run ./prepare_manager.sh, which mints it "+
			"and writes it out)", need)
	}
	token, err := wire.ParseEnrollmentToken(r.cfg.EnrollToken)
	if err != nil {
		return err
	}
	r.enrollToken = token
	r.enrollKey = token.Key()
	return nil
}

func (r *Runner) hasEnrollHTTPSStep() bool {
	for _, steps := range r.scn.Lanes {
		for _, step := range steps {
			if step.Kind == "enroll_https" {
				return true
			}
		}
	}
	return false
}

// bootstrap gives one agent the identity it runs the whole scenario under. This
// is SETUP, not load: the measurement clock starts after the last agent has one
// (see Run), and neither path records a metric -- folding one request per agent
// into the `enroll_https` counters would corrupt both those numbers and any
// `expected` block over them.
func (r *Runner) bootstrap(ag *agent) (wire.Identity, error) {
	if r.cfg.Bootstrap == Bootstrap1515 {
		ident, err := wire.Enroll(r.cfg.Manager, r.cfg.RegPort, ag.name, r.cfg.Timeout)
		if err != nil {
			return wire.Identity{}, fmt.Errorf("enroll %s over 1515: %w", ag.name, err)
		}
		return ident, nil
	}
	return r.enrollWithToken(ag)
}

// enrollWithToken bootstraps one agent the way a 5.x agent handed a token does:
// POST /enroll on the same HTTPS listener it will use afterwards, with the
// `wazuh-enroll+jwt` bearer minted from the run's enrollment token (issue
// #39054). It is the path that works against a manager whose <use_password> is
// the installed default, so no configuration flip is needed to benchmark one.
//
// Anything but a 200 aborts the run as a setup failure: a fleet that half
// enrolled measures nothing meaningful, and the three likely statuses have three
// different fixes, so each says its own.
func (r *Runner) enrollWithToken(ag *agent) (wire.Identity, error) {
	if ag.enroll == nil || r.enrollToken == nil {
		// prepareEnrollToken() runs before buildAgents, so this is a programming error.
		return wire.Identity{}, errors.New("no enrollment token client for the bootstrap")
	}
	res, err := enrollhttps.Request(ag.enroll, r.enrollKey, r.enrollToken.ID, ag.name, ag.enrollVersion(), now())
	if err != nil {
		return wire.Identity{}, fmt.Errorf("enroll %s over POST /enroll: %w", ag.name, err)
	}
	if res.Status != 200 {
		return wire.Identity{}, fmt.Errorf("enroll %s over POST /enroll: the manager answered %d -- %s",
			ag.name, res.Status, bootstrapHint(res.Status))
	}
	return wire.Identity{ID: res.AgentID, Name: ag.name, Key: res.Key, ReenrollSecret: res.ReenrollSecret}, nil
}

// bootstrapHint turns the contract statuses of POST /enroll into the action they
// call for. They are ordinary results for a measured step, but for the bootstrap
// each one is a setup mistake with its own remedy.
func bootstrapHint(status int) string {
	switch status {
	case 401:
		return "it refused the bearer: the token is unknown, expired or revoked (mint a fresh one), " +
			"or this host's clock is outside the accepted window"
	case 403:
		return "authd refused the token's use: it is out of uses (mint one without --max-uses, which is " +
			"unlimited), or it was revoked or expired"
	case 409:
		return "duplicate agent name: a previous run's bench-* agents are still registered -- " +
			"run ./cleanup_agents.sh first"
	default:
		return "an answer the enrollment contract does not describe for this route"
	}
}

// enrollVersion is the version this agent claims when it enrolls: its fleet's
// declared agent version, else the sender's default.
func (a *agent) enrollVersion() string {
	if v := a.fleet.Start.AgentVersion; v != "" {
		return v
	}
	return enrollHTTPSVersion
}

// runEnrollHTTPS sends one POST /enroll with the enrollment-token bearer, for a
// NEW agent name derived from this agent's own (`<name>-tk-<n>`, keeping the
// `bench-` prefix cleanup_agents.sh keys on). The identity the answer mints is
// recorded and dropped: the step measures the path, it does not adopt the
// result -- this simulated agent keeps running under the identity its bootstrap
// gave it.
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

	a.r.requestStarted()
	res, err := enrollhttps.Request(a.enroll, a.r.enrollKey, a.r.enrollToken.ID, name, a.enrollVersion(), now())
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
