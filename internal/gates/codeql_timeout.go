package gates

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

func explainCodeQLTimeout(outcome CodeQLOutcome, ctx context.Context, budget time.Duration) CodeQLOutcome {
	if !errors.Is(ctx.Err(), context.DeadlineExceeded) && !strings.Contains(outcome.Result.Detail, "process timed out") {
		return outcome
	}
	outcome.Result.Status = Error
	outcome.Result.Detail = fmt.Sprintf("CodeQL timeout during %s: %s; overall budget=%s (version, database creation and all language analyses); per-command cap=%s; the earliest parent, operation or command deadline wins. Cold query compilation may exhaust this budget. Inspect captured CodeQL diagnostics and compilation-cache readiness; if appropriate, configure quality.codeql.timeout and run the same quality profile again. Partial analysis is not a pass.", outcome.Stage, outcome.Result.Detail, budget, codeQLCommandTimeout)
	return outcome
}
