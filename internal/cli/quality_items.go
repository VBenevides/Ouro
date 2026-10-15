package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/VBenevides/Ouro/internal/config"
	"github.com/VBenevides/Ouro/internal/quality"
)

type qualityItemFlag struct {
	names     []string
	requested bool
}

func (f *qualityItemFlag) String() string { return strings.Join(f.names, ",") }

func (f *qualityItemFlag) Set(value string) error {
	f.requested = true
	if value == "" {
		return nil
	}
	return appendQualityItems(&f.names, value)
}

// Normalize the optional item value before flag.Parse, which otherwise consumes
// the next option as a required value. Preserve values of other string flags.
func qualityItemArguments(args []string) []string {
	normalized := make([]string, 0, len(args))
	for index := 0; index < len(args); index++ {
		arg := args[index]
		switch arg {
		case "--":
			return append(normalized, args[index:]...)
		case "--root", "-root", "--stage", "-stage", "--run-id", "-run-id":
			normalized = append(normalized, arg)
			if index+1 < len(args) {
				index++
				normalized = append(normalized, args[index])
			}
		case "--item", "-item":
			value := ""
			if index+1 < len(args) && !strings.HasPrefix(args[index+1], "-") {
				index++
				value = args[index]
			}
			normalized = append(normalized, arg+"="+value)
		default:
			normalized = append(normalized, arg)
		}
	}
	return normalized
}

func runQualityItems(root string, cfg config.Config, jsonOutput bool, out, errOut io.Writer) int {
	// Listing covers all configured stages, not just the default execution profile.
	plan, err := quality.BuildPlan(context.Background(), quality.PlanOptions{Root: root, Config: cfg, Profile: "strict"})
	if err != nil {
		_, _ = fmt.Fprintf(errOut, "ouro quality items: %v\n", err)
		return 1
	}
	items := quality.AvailableItems(plan)
	if jsonOutput {
		err = json.NewEncoder(out).Encode(struct {
			Items []string `json:"items"`
		}{items})
	} else {
		for _, item := range items {
			if _, err = fmt.Fprintln(out, item); err != nil {
				break
			}
		}
	}
	if err != nil {
		_, _ = fmt.Fprintf(errOut, "ouro quality items: %v\n", err)
		return 1
	}
	return 0
}
