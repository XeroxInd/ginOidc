package ginOidc

import (
	"github.com/casbin/casbin/v2"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

// NewAuthorizer returns the authorizer, uses a Casbin enforcer as input
func NewAuthorizer(e *casbin.Enforcer) gin.HandlerFunc {
	a := &OidcAuthorizer{enforcer: e}
	return func(c *gin.Context) {
		if !a.CheckPermission(c) {
			a.RequirePermission(c)
		}
	}
}

// OidcAuthorizer stores the casbin handler
type OidcAuthorizer struct {
	enforcer *casbin.Enforcer
}

// CheckPermission checks the user/method/path combination from the request.
// Returns true (permission granted) or false (permission forbidden)
func (a *OidcAuthorizer) CheckPermission(c *gin.Context) bool {
	user, err := GetIdentity(c)
	if err != nil {
		log.Error(err)
		return false
	}

	method := c.Request.Method
	path := c.Request.URL.Path

	for _, group := range user.Groups {
		allowed, err := a.enforcer.Enforce(group, path, method)
		if err != nil {
			log.Error(err)
		}
		if allowed {
			return allowed
		}
	}
	return false
}

// RequirePermission returns the 403 Forbidden to the client
func (a *OidcAuthorizer) RequirePermission(c *gin.Context) {
	c.AbortWithStatus(403)
}
