package workflow

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/VBenevides/Ouro/internal/config"
	"github.com/VBenevides/Ouro/internal/gates"
)

func TestQualityNodeDependencyContext(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node is required for ESM resolution fixture")
	}
	for _, scenario := range []string{"local", "global-fallback", "local-failure"} {
		t.Run(scenario, func(t *testing.T) {
			root := t.TempDir()
			write := func(name, content string, mode os.FileMode) {
				t.Helper()
				path := filepath.Join(root, name)
				if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(content), mode); err != nil {
					t.Fatal(err)
				}
			}
			write(".gitignore", "node_modules/\n", 0644)
			write("frontend/package.json", `{"type":"module"}`, 0644)
			write("frontend/index.js", "export const value = 1;", 0644)
			write("frontend/node_modules/fixture/package.json", `{"type":"module","exports":"./index.js"}`, 0644)
			write("frontend/node_modules/fixture/index.js", `export default "component-local";`, 0644)
			write("frontend/eslint.config.js", `import value from 'fixture'; if(value !== 'component-local') throw Error('wrong package'); export default [];`, 0644)
			if output, err := exec.Command("git", "-C", root, "init", "-q").CombinedOutput(); err != nil {
				t.Fatalf("git init: %v %s", err, output)
			}
			script := "#!/usr/bin/env node\n" + `
const fs = require('node:fs');
const {pathToFileURL} = require('node:url');
if (process.argv.includes('--version')) { console.log('fixture-local-1'); process.exit(0); }
if (!process.cwd().includes('ouro-inputs-')) throw Error('not isolated');
import(pathToFileURL(process.cwd() + '/eslint.config.js')).then(() => {
 fs.writeFileSync('node_modules/fixture/index.js', 'export default "component-local"; // private edit');
 console.log('resolved-local-package');
 process.exit(FAILURE);
}).catch(error => { console.error(error); process.exit(2); });
`
			exitCode := "0"
			if scenario == "local-failure" {
				exitCode = "1"
			}
			script = strings.ReplaceAll(script, "FAILURE", exitCode)
			global := t.TempDir()
			for _, tool := range []string{"eslint", "tsc"} {
				globalScript := "#!/usr/bin/env node\nconsole.error('global must not override local'); process.exit(3);\n"
				if scenario == "global-fallback" {
					globalScript = script
				}
				if err := os.WriteFile(filepath.Join(global, tool), []byte(globalScript), 0755); err != nil {
					t.Fatal(err)
				}
				if scenario != "global-fallback" {
					write("frontend/node_modules/fixture-tool/"+tool+".cjs", script, 0755)
					bin := filepath.Join(root, "frontend/node_modules/.bin")
					if err := os.MkdirAll(bin, 0755); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink("../fixture-tool/"+tool+".cjs", filepath.Join(bin, tool)); err != nil {
						t.Fatal(err)
					}
					write("node_modules/.bin/"+tool, globalScript, 0755)
				}
			}
			t.Setenv("PATH", global+string(os.PathListSeparator)+os.Getenv("PATH"))
			cfg := config.Default(root)
			write("frontend/tsconfig.json", `{}`, 0644)
			write("frontend/index.ts", "export {};", 0644)
			result, err := RunQuality(context.Background(), QualityOptions{Root: root, RunID: scenario, Stage: "fast", Items: []string{"javascript-lint", "typescript-typecheck"}, Config: cfg, Ephemeral: true, CheckReadiness: true})
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Results) != 2 {
				t.Fatalf("expected two gates: %+v", result.Results)
			}
			for _, check := range result.Results {
				expected := gates.Pass
				if scenario == "local-failure" {
					expected = gates.Fail
				}
				if check.Status != expected || !strings.Contains(check.Stdout, "resolved-local-package") {
					t.Fatalf("unexpected gate: %+v", check)
				}
			}
			original, err := os.ReadFile(filepath.Join(root, "frontend/node_modules/fixture/index.js"))
			if err != nil || string(original) != `export default "component-local";` {
				t.Fatalf("checkout dependency changed: %s %v", original, err)
			}
		})
	}
}
