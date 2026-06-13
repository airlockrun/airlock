package dbqapi

import "github.com/airlockrun/airlock/db/dbq"

func badDBQ() {
	q := dbq.New()
	_ = q.GetUserByID("x") // want `direct dbq.Queries.GetUserByID call in api/.*`
	_, _ = q.ListAgents()  // want `direct dbq.Queries.ListAgents call in api/.*`
}

func allowedDBQ() {
	q := dbq.New()
	// airlockvet:allow-dbq reason: bootstrap path before any service exists
	_ = q.GetUserByID("x")
}
