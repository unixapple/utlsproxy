package main

import (
	"github.com/unixapple/utlsproxy/internal/cli"
	"os"
)

var version = "0.1.0-dev"

func main() { os.Exit(cli.Execute(os.Args[1:], os.Stdout, os.Stderr, version)) }
