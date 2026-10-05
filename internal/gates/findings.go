package gates

import (
	"fmt"

	"github.com/VBenevides/Ouro/internal/findings"
)

func RecordFindings(store findings.Store, results []Result) error {
	for _, result := range results {
		if result.Status == Pass {
			if err := store.ResolveIfPresent("gate/"+result.Name, "gate passed on a fresh rerun", "ouro"); err != nil {
				return err
			}
			continue
		}
		if result.Status == Skipped {
			continue
		}
		severity := "medium"
		if result.Required {
			severity = "high"
		}
		id := "gate/" + result.Name
		finding, err := findings.New(id, "gate", severity, result.Category, fmt.Sprintf("Gate %s returned %s: %s", result.Name, result.Status, result.Detail), "Make the configured gate pass or record an approved exception.", []string{result.InputHash})
		if err != nil {
			return err
		}
		if err := store.Detect(finding, "ouro"); err != nil {
			return err
		}
	}
	return nil
}
