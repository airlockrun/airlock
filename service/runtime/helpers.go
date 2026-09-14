package runtime

import "github.com/airlockrun/airlock/apihelpers"

var (
	parseUUID = apihelpers.ParseUUID
	toPgUUID  = apihelpers.ToPgUUID
	pgUUID    = apihelpers.PgUUID
)
