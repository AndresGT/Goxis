package middleware

import (
	"strings"

	goxis "github.com/AndresGT/Goxis/app"
	"github.com/AndresGT/Goxis/security/token"
)

// Role maps a token role name to its permission grants.
type Role struct {
	Name        string
	Permissions []string
}

// RBAC validates the request's access token and checks the policy Goxis
// resolved for the selected route. It implements goxis.Authorizer; it does not
// register routes or configure rate limits.
type RBAC struct {
	manager AccessTokenValidator
	roles   map[string]map[string]struct{}
}

func NewRBAC(manager AccessTokenValidator, roles ...Role) *RBAC {
	rbac := &RBAC{manager: manager, roles: make(map[string]map[string]struct{}, len(roles))}
	for _, role := range roles {
		name := strings.TrimSpace(role.Name)
		if name == "" {
			continue
		}
		grants := make(map[string]struct{}, len(role.Permissions))
		for _, permission := range role.Permissions {
			permission = strings.TrimSpace(permission)
			if permission != "" {
				grants[permission] = struct{}{}
			}
		}
		rbac.roles[name] = grants
	}
	return rbac
}

func (r *RBAC) Authorize(ctx *goxis.Context, policy goxis.Policy) error {
	if r == nil || r.manager == nil {
		return goxis.ErrAccessControlUnavailable
	}
	claims, ok := ClaimsFromContext(ctx)
	if !ok {
		parts := strings.Fields(ctx.Request.Header.Get("Authorization"))
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" {
			return goxis.ErrUnauthenticated
		}
		var err error
		claims, err = r.manager.ValidateAccessToken(parts[1])
		if err != nil {
			return goxis.ErrUnauthenticated
		}
		setClaims(ctx, claims)
	}
	ctx.MarkAuthenticated()

	userRoles := make(map[string]struct{}, len(claims.Roles))
	grants := make(map[string]struct{}, len(claims.Permissions))
	for _, role := range claims.Roles {
		userRoles[role] = struct{}{}
		for permission := range r.roles[role] {
			grants[permission] = struct{}{}
		}
	}
	for _, permission := range claims.Permissions {
		grants[permission] = struct{}{}
	}
	for _, role := range policy.Roles {
		if _, ok := userRoles[role]; !ok {
			return goxis.ErrForbidden
		}
	}
	if len(policy.AnyRole) > 0 {
		matched := false
		for _, role := range policy.AnyRole {
			if _, ok := userRoles[role]; ok {
				matched = true
				break
			}
		}
		if !matched {
			return goxis.ErrForbidden
		}
	}
	for _, permission := range policy.Permissions {
		if !hasPermission(grants, permission) {
			return goxis.ErrForbidden
		}
	}
	return nil
}

func setClaims(ctx *goxis.Context, claims token.Claims) {
	ctx.Set(ClaimsContextKey, claims)
	ctx.Set(UserIDContextKey, claims.UserID)
	ctx.Set("user_claims", claims)
	ctx.Set("user_id", claims.UserID)
	for key, value := range claims.CustomData {
		ctx.Set(key, value)
	}
}

func hasPermission(grants map[string]struct{}, permission string) bool {
	if _, ok := grants["*"]; ok {
		return true
	}
	if _, ok := grants[permission]; ok {
		return true
	}
	parts := strings.SplitN(permission, ":", 2)
	if len(parts) == 2 {
		if _, ok := grants[parts[1]]; ok {
			return true
		}
		if _, ok := grants[parts[0]+":*"]; ok {
			return true
		}
		if _, ok := grants["*:"+parts[1]]; ok {
			return true
		}
	}
	return false
}
