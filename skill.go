package ouro

import _ "embed"

//go:embed skills/ouro-quality/SKILL.md
var skillFile string

// Skill returns the ouro-quality SKILL.md content embedded at build time.
func Skill() string {
	return skillFile
}
