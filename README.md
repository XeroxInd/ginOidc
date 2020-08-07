# ginOidc

## Introduction

ginOidc package allow to manage authentication (via [OpenID](https://fr.wikipedia.org/wiki/OpenID)) and authorization (via [Casbin](https://casbin.org/)) in a [Gin-Gonic](https://gin-gonic.com/) application.

## Authentication

Authentication is managed via a Middleware.

Exemple :

```go
func (srv *Server) InitRouter() (err error) {
	srv.router = gin.Default()

	srv.AuthParam, err = auth.InitAuth(srv.Config.BaseUrl, srv.router)
	if err != nil {
		log.Fatal(err)
	}
	srv.CookieStore = cookie.NewStore([]byte("secret"))

	srv.router.Use(sessions.Sessions("agritracking", srv.CookieStore))
	// manage authentication, all routes declared after this line will use the Middleware.
	srv.router.Use(ginoidc.Init(srv.AuthParam))
	// manage authorization, all routes declared after this line will use the Middleware.
	enforcer, err := casbin.NewEnforcer("authz_model.conf", "authz_policy.csv")
	if err != nil {
		log.Fatal(err)
	}
	srv.router.Use(ginoidc.NewAuthorizer(enforcer))

  srv.registerStatic() // Declare static routes (assets, etc...)
	srv.registerPages() // Declare dynamic routes
	return
}
```

With `auth.InitAuth` as :

```go
func InitAuth(baseUrl string, router *gin.Engine) (authParam gin_oidc.InitParams, err error) {
	issuer, err := url.Parse("https://auth.solutions.im/auth/realms/solutions")
	if err != nil {
		return
	}
	clientURL, err := url.Parse(baseUrl)
	if err != nil {
		return
	}
	postLogout, err := url.Parse(baseUrl)
	if err != nil {
		return
	}

	authParam = gin_oidc.InitParams{
		Router:       router,
		ClientId:     "test",
		ClientSecret: "0c862cea-64ca-4b07-b50f-2dca81a7a0b2",
		Issuer:       *issuer,
		ClientUrl:    *clientURL,
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
		ErrorHandler: func(c *gin.Context) {
			// gin_oidc pushes a new error before any "ErrorHandler" invocation
			// message := c.Errors.Last().Error()
			// redirect to ErrorEndpoint with error message
			c.Redirect(http.StatusInternalServerError, baseUrl+"error.html")
			// redirectToErrorPage(c, "http://example2.domain/error", message)
			// when "ErrorHandler" ends "c.Abort()" is invoked - no further handlers will be invoked
		},
		PostLogoutUrl: *postLogout,
	}
	return
}
```

## Authorization

Authorization also use the middleware principle, they need two additional file to define policy.

Exemple : `auto_model.conf` that define how to read and interpret policies

```conf
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = keyMatch(r.sub, p.sub) && keyMatch(r.obj, p.obj) && (r.act == p.act || p.act == "*")
```

Exemple : `authz_policy.csv`that define the access (RBAC based here) policies

```csv
# public ressources
p, /agritracking/*, /vendors/*, GET
p, /agritracking/*, /build/*, GET
p, /agritracking/*, /images/*, GET
p, /agritracking/*, /favicon.ico, GET
p, /agritracking/*, /, GET

# operator
p, /agritracking/operator, /production/*, *

# supervisor
p, /agritracking/supervisor, /production/*, *
p, /agritracking/supervisor, /reporting/*, *

# administrator
p, /agritracking/administrator, /production/*, *
p, /agritracking/administrator, /reporting/*, *
p, /agritracking/administrator, /admin/*, *

# customer
p, /agritracking/customer, /reporting/*, *
```

