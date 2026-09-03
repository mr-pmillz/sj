package cli

import (
	"fmt"

	"github.com/mr-pmillz/sj/pkg/config"
	"github.com/mr-pmillz/sj/pkg/privateheaders"
)

type privateHeaderRedactedError struct {
	message string
}

func (failure *privateHeaderRedactedError) Error() string { return failure.message }

func loadPrivateHeaders(cfg *config.Config, explicitURLs []string) error {
	if cfg == nil || cfg.HeaderFile == "" || cfg.PrivateHeaders != nil {
		return nil
	}
	if cfg.TargetExplicit && cfg.APITarget != "" {
		explicitURLs = append(append([]string(nil), explicitURLs...), cfg.APITarget)
	}
	policy, err := privateheaders.Load(cfg.HeaderFile, explicitURLs, cfg.Headers)
	if err != nil {
		return fmt.Errorf("load --header-file: %w", err)
	}
	cfg.PrivateHeaders = policy
	return nil
}

func automateExplicitURLs(cfg *config.Config, sources []automateSource) []string {
	if cfg == nil || (cfg.SwaggerURL == "" && cfg.AutomateURLFile == "") {
		return nil
	}
	urls := make([]string, 0, len(sources))
	for _, source := range sources {
		if source.url != "" {
			urls = append(urls, source.url)
		}
	}
	return urls
}

func fullWorkflowExplicitURLs(base *config.Config, options fullWorkflowCLIOptions) ([]string, error) {
	if options.TargetsFile == "" {
		return nil, nil
	}
	targetConfig := cloneWorkflowConfig(base)
	targetConfig.SwaggerURL = ""
	targetConfig.BruteURLFile = options.TargetsFile
	targets, err := bruteTargets(targetConfig)
	if err != nil {
		return nil, fmt.Errorf("load full workflow target origins: %w", err)
	}
	return targets, nil
}

func redactPrivateError(cfg *config.Config, err error) error {
	if err == nil || cfg == nil || cfg.PrivateHeaders == nil {
		return err
	}
	message := cfg.PrivateHeaders.RedactString(err.Error())
	if message == err.Error() {
		return err
	}
	// Do not retain the original error: a wrapped cause containing reflected
	// private material would remain reachable through errors.Unwrap even when
	// the displayed message was scrubbed.
	return &privateHeaderRedactedError{message: message}
}
