package main

import (
	"strings"

	"github.com/spf13/viper"
)

// EnvReplacer replaces `-` to `_`.
// This is used to map flag like `--my-param` to environment variables like `MY_PARAM`.
var envReplacer = strings.NewReplacer("-", "_")

func init() {
	viper.SetEnvPrefix("ARKD")
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(envReplacer)
}
