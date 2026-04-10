// process-tracer is an eBPF-based process and network tracer with OpenTelemetry span integration.
package main

import (
	"context"
	_ "embed"
	"fmt"
	"log"
	"os"

	"github.com/mrzor/process-tracer/internal/config"
	"github.com/urfave/cli/v3"
)

//go:embed LICENSE
var licenseText string

// Version information injected at build time.
var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("Error: %v", err)
	}
}

func run() error {
	// Check for symlink mode before urfave/cli parses args.
	// In symlink mode, args like "-c" are shell flags, not our flags.
	envCfg, err := config.ParseEnvConfig()
	if err != nil {
		return fmt.Errorf("failed to parse environment config: %w", err)
	}

	isSymlink, err := config.DetectSymlinkMode(envCfg.Mode)
	if err != nil {
		return err
	}

	if isSymlink {
		cfg, err := config.ParseSymlinkMode(os.Args, envCfg)
		if err != nil {
			return err
		}
		return runTrace(cfg)
	}

	app := &cli.Command{
		Name:    "process-tracer",
		Usage:   "eBPF-based process and network tracer with OpenTelemetry span integration",
		Version: config.FormatVersionString(version, commit, date),
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:  "license",
				Usage: "Display license information and exit",
				Action: func(_ context.Context, _ *cli.Command, b bool) error {
					if b {
						fmt.Println(licenseText)
						return cli.Exit("", 0)
					}
					return nil
				},
			},
		},
		Commands: []*cli.Command{
			traceCommand(),
			daemonCommand(),
		},
	}

	return app.Run(context.Background(), os.Args)
}
