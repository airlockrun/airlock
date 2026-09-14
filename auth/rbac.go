package auth

// Role is a tenant role — what a user can do in Airlock as a platform,
// independent of any per-agent access. Mirrors agentsdk.Access (the
// per-agent axis) so the two gates read the same way.
type Role string

const (
	RoleAdmin   Role = "admin"
	RoleManager Role = "manager"
	RoleUser    Role = "user"
)

// roleLevel maps tenant roles to their hierarchy level.
// Higher level = more privileges. admin > manager > user.
var roleLevel = map[Role]int{
	RoleAdmin:   3,
	RoleManager: 2,
	RoleUser:    1,
}

// AtLeast reports whether r ranks at or above min. An unknown role
// (including the empty string) ranks below everything.
func (r Role) AtLeast(min Role) bool {
	return r.Valid() && min.Valid() && roleLevel[r] >= roleLevel[min]
}

func (r Role) Valid() bool { return roleLevel[r] != 0 }
