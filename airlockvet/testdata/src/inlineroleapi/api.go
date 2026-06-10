package inlineroleapi

import "github.com/airlockrun/airlock/auth"

type principal struct{ Role auth.Role }

func badRoleCheck(p principal) bool {
	return p.Role.AtLeast(auth.RoleAdmin) // want `inline reference to RoleAdmin outside authz/.*`
}

func badRoleCompare(p principal) bool {
	return p.Role == auth.RoleManager // want `inline reference to RoleManager outside authz/.*`
}

func allowedRoleCheck(p principal) bool {
	// airlockvet:allow-inline-role reason: documented exception
	return p.Role.AtLeast(auth.RoleAdmin)
}

// Mentioning the Role TYPE in a signature is fine.
func mentionsType(_ auth.Role) {}
