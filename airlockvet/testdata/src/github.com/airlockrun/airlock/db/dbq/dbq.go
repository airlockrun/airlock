package dbq

type Queries struct{}

func New() *Queries { return &Queries{} }

func (q *Queries) GetUserByID(id string) error { return nil }

func (q *Queries) ListAgents() ([]string, error) { return nil, nil }
