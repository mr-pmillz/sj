package cli

import (
	"context"

	"github.com/mr-pmillz/sj/pkg/config"
	"github.com/mr-pmillz/sj/pkg/httpclient"
	"github.com/mr-pmillz/sj/pkg/specsource"
)

func loadSpec(ctx context.Context, cfg *config.Config, client *httpclient.Client) ([]byte, error) {
	return specsource.Load(ctx, cfg, client)
}

func newHTTPClient(cfg *config.Config) (*httpclient.Client, error) {
	client := httpclient.NewClient(cfg)
	if client.InitErr != nil {
		return nil, client.InitErr
	}
	return client, nil
}
