package main

import (
	"context"

	"github.com/airlockrun/airlock/api"
	"github.com/airlockrun/airlock/config"
	"github.com/airlockrun/airlock/db"
	"go.uber.org/zap"
)

func initOIDC(_ context.Context, _ *config.Config, _ *db.DB, _ string, _ *zap.Logger) api.OIDCRoutes {
	return nil
}
