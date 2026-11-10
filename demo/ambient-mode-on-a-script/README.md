# ambient-mode-on-a-script

Measure what a script that runs before your commands (a pre-command hook, a shell wrapper,
anything exec'd often) costs, using process-tracer's ambient mode.

- `spy.sh`      — `sudo -E` it. Traces `$SPY_TARGET` (default `/usr/sbin/spy.sh`) system-wide and
                  writes `/tmp/spy-spans-<ts>.jsonl` (0600, owned by you). Example:
                  `SPY_TARGET=/path/to/script sudo -E demo/ambient-mode-on-a-script/spy.sh`
- `spy.yaml`    — rule template; `spy.sh` fills in the kernel comm (the 15-char basename of the
                  target). Only works if the target is exec'd directly, not `bash script`.
                  `add_debug_attributes` is ON: spans carry `debug.argv` **and the full
                  environment** — keep the output local.
- `jaegerize.sh FILE` — podman Jaeger on 127.0.0.1:16686, replays and follows FILE.
