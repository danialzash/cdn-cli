package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/pflag"
)

func registerExplicitBoolFlag(flags *pflag.FlagSet, name, shorthand string, usage string) {
	flags.Bool(name, false, usage+" (supports =true or =false)")
	if shorthand != "" {
		flags.Lookup(name).Shorthand = shorthand
	}
}

func explicitBoolChanged(flags *pflag.FlagSet, name string) (changed bool, value bool) {
	if !flags.Changed(name) {
		return false, false
	}
	v, err := flags.GetBool(name)
	if err != nil {
		return true, false
	}
	return true, v
}

func validateExplicitBoolSyntax(raw string) error {
	raw = strings.TrimSpace(strings.ToLower(raw))
	switch raw {
	case "true", "false", "1", "0", "t", "f", "yes", "no":
		return nil
	default:
		return fmt.Errorf("boolean flag value must be true or false, got %q", raw)
	}
}
