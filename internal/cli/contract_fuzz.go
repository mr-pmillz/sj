package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/mr-pmillz/sj/pkg/config"
	"github.com/mr-pmillz/sj/pkg/contract"
	"github.com/mr-pmillz/sj/pkg/output"
	"github.com/spf13/cobra"
	"go.yaml.in/yaml/v4"
)

const minimumContractDelay = 100 * time.Millisecond

type contractFuzzOptions struct {
	MaxRequests   int
	Delay         time.Duration
	MaxCases      int
	Confirmations int
	Seed          uint64
	Only          []string
	Exclude       []string
	KeepRecords   bool
	EmitSuite     string
	Format        string
	FailOn        string
	Progress      bool
}

var contractFuzz contractFuzzOptions

var contractFuzzCmd = &cobra.Command{
	Use:   "fuzz --target API_BASE (-l FILE | -u URL)",
	Short: "Generate and run system-level test cases for every documented operation.",
	Long: `Generate test cases from the API contract, run them and report what the
responses show.

sj first obtains one accepted valid request for every operation, creating the
test records the paths need. From each accepted request it derives variants:
no credential and a made-up credential on operations that declare security,
contract-violating and hostile input, records that do not exist, wrong login
credentials and methods the contract does not define. Findings in the
security categories are re-run on new records, and the records are removed.

Without --accept-risk, sj sends only safe methods and skips paths that
contain a guarded word. With it, a request that changes or deletes a record
by its path identifier addresses a record sj created, or carries a made-up
marker value such as "sj-nan". Request bodies carry generated values, so
point this command at a test environment.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		return runContractFuzz(cmd.Context(), cfg, contractFuzz, cmd.OutOrStdout(), cmd.ErrOrStderr())
	},
}

func init() {
	flags := contractFuzzCmd.Flags()
	flags.IntVar(&contractFuzz.MaxRequests, "max-requests", 1000, "Hard request budget, including record setup, re-runs and cleanup.")
	flags.DurationVar(&contractFuzz.Delay, "delay", 200*time.Millisecond, "Delay between sequential requests; minimum 100ms except on a loopback target.")
	flags.IntVar(&contractFuzz.MaxCases, "max-cases", 24, "Maximum contract-violating inputs tried per operation.")
	flags.IntVar(&contractFuzz.Confirmations, "confirm", 1, "Times each security finding is re-run on new test records (0-5).")
	flags.Uint64Var(&contractFuzz.Seed, "seed", 0, "Seed for generated identifiers. A random seed is used and reported when zero.")
	flags.StringArrayVar(&contractFuzz.Only, "operation", nil, "Test only this operation, as 'METHOD /path' or an operationId; repeatable.")
	flags.StringArrayVar(&contractFuzz.Exclude, "exclude-operation", nil, "Never send this operation, as 'METHOD /path' or an operationId; repeatable.")
	flags.StringSliceVar(&cfg.ExcludeMethods, "exclude", nil, "Never send this HTTP method, such as DELETE (repeat or use a comma-separated list). Records that sj then cannot remove stay on the target and are counted in the report.")
	flags.BoolVar(&contractFuzz.KeepRecords, "keep-records", false, "Leave the created test records on the target.")
	flags.StringVar(&contractFuzz.EmitSuite, "emit-suite", "", "Write the executed cases to this file as a suite that 'sj contract --suite' replays.")
	flags.StringVarP(&contractFuzz.Format, "output-format", "F", "json", "Report format: json, markdown, sarif, or junit.")
	flags.StringVar(&contractFuzz.FailOn, "fail-on", "low", "Exit nonzero when a finding has at least this severity: critical, high, medium, low, info, or none.")
	flags.BoolVar(&contractFuzz.Progress, "progress", false, "Show request counts and case names on stderr.")
	flags.BoolVar(&cfg.AcceptRisk, "accept-risk", false, "Allow state-changing operations on test records that sj creates.")
	flags.BoolVar(&cfg.StoreResponses, "store-responses", false, "Keep a bounded response excerpt for each case that raised a finding.")
	flags.Int64Var(&cfg.MaxStoredResponseBytes, "max-stored-response-bytes", 64*1024, "Maximum response bytes retained per excerpt (at most 2048 are kept).")
	contractCmd.AddCommand(contractFuzzCmd)
}

// writeContractReport renders a report in the requested format.
func writeContractReport(out io.Writer, report contract.Report, format string) error {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "json":
		encoder := json.NewEncoder(out)
		encoder.SetIndent("", "  ")
		return encoder.Encode(report)
	case "markdown", "md":
		return contract.WriteMarkdown(out, report)
	case "sarif":
		return contract.WriteSARIF(out, report)
	case "junit":
		return contract.WriteJUnit(out, report)
	}
	return fmt.Errorf("unsupported contract report format %q", format)
}

func validContractFormat(format string, allowed ...string) error {
	for _, name := range allowed {
		if strings.EqualFold(strings.TrimSpace(format), name) {
			return nil
		}
	}
	return fmt.Errorf("output format must be one of %s", strings.Join(allowed, ", "))
}

// terminalSafe removes control characters from contract-supplied names.
func terminalSafe(text string) string {
	return strings.Map(func(char rune) rune {
		if char < 0x20 || (char >= 0x7f && char <= 0x9f) {
			return -1
		}
		return char
	}, text)
}

func loopbackTarget(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil {
		return false
	}
	addr, err := netip.ParseAddr(parsed.Hostname())
	return err == nil && addr.Unmap().IsLoopback()
}

func runContractFuzz(ctx context.Context, cfg *config.Config, options contractFuzzOptions, out, notes io.Writer) error {
	if err := validContractFormat(options.Format, "json", "markdown", "md", "sarif", "junit"); err != nil {
		return err
	}
	if options.FailOn != "none" && !contract.SeverityAtLeast(options.FailOn, "info") {
		return errors.New("--fail-on must be critical, high, medium, low, info, or none")
	}
	if options.MaxRequests <= 0 || options.MaxCases <= 0 || options.Confirmations < 0 || options.Confirmations > 5 {
		return errors.New("--max-requests and --max-cases must be positive, and --confirm between 0 and 5")
	}
	if options.Delay < minimumContractDelay && !loopbackTarget(cfg.APITarget) {
		return fmt.Errorf("--delay must be at least %s for a target that is not loopback", minimumContractDelay)
	}
	if options.EmitSuite != "" && options.EmitSuite == cfg.Outfile {
		return errors.New("--emit-suite and --outfile must name different files")
	}
	settings := contract.FuzzOptions{
		RunOptions:    contract.RunOptions{Delay: options.Delay, MaxRequests: options.MaxRequests, Seed: options.Seed},
		MaxCases:      options.MaxCases,
		Confirmations: options.Confirmations,
		Only:          options.Only,
		Exclude:       options.Exclude,
		KeepRecords:   options.KeepRecords,
	}
	if options.Progress {
		settings.Progress = func(requests int, name string) {
			_, _ = fmt.Fprintf(notes, "[%d/%d] %s\n", requests, options.MaxRequests, terminalSafe(name))
		}
	}
	report, suite, runErr := contract.Fuzz(ctx, cfg, settings)
	if runErr != nil && report.Cases == nil {
		return runErr
	}
	if options.EmitSuite != "" {
		err := output.WriteFileAtomically(options.EmitSuite, func(w io.Writer) error {
			data, err := yaml.Dump(suite)
			if err != nil {
				return err
			}
			_, err = w.Write(data)
			return err
		})
		if err != nil {
			return fmt.Errorf("write generated suite: %w", err)
		}
	}
	write := func(w io.Writer) error { return writeContractReport(w, report, options.Format) }
	var err error
	if cfg.Outfile != "" {
		err = output.WriteFileAtomically(cfg.Outfile, write)
	} else {
		err = write(out)
	}
	if err != nil {
		return fmt.Errorf("write contract report: %w", err)
	}
	if err := contract.WriteSummary(notes, report); err != nil {
		return err
	}
	if runErr != nil {
		return runErr
	}
	failing := 0
	for _, finding := range report.Findings {
		if options.FailOn != "none" && contract.SeverityAtLeast(finding.Severity, options.FailOn) {
			failing++
		}
	}
	if failing != 0 {
		return fmt.Errorf("%d findings at or above %s severity", failing, options.FailOn)
	}
	return nil
}
