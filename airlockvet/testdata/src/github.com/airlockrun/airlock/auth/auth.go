package auth

type Role string

const (
	RoleAdmin   Role = "admin"
	RoleManager Role = "manager"
	RoleUser    Role = "user"
)

func (r Role) AtLeast(min Role) bool { return r == min }
