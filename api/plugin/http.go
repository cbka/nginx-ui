package plugin

import (
	"github.com/0xJacky/Nginx-UI/internal/middleware"
	plugin "github.com/0xJacky/Nginx-UI/internal/plugin"
	"github.com/0xJacky/Nginx-UI/internal/plugin/capability"
	"github.com/gin-gonic/gin"
)

// InitHTTPRouter registers the http capability route. It is kept separate
// from InitRouter because it is not a management endpoint: it forwards
// arbitrary requests to a plugin and streams the reply back.
//
// It takes the /api group itself rather than the authenticated one because a
// browser WebSocket cannot send an Authorization header: upgrade requests
// authenticate and proxy like the host's own WebSocket routes (credentials in
// the query string), every other request uses the header based chain.
func InitHTTPRouter(r *gin.RouterGroup) {
	r.Any("/plugins/:id/http/*path",
		middleware.ForWebSocketUpgrade(middleware.RequireWebSocketOrigin(), func(c *gin.Context) { c.Next() }),
		middleware.ForWebSocketUpgrade(middleware.AuthRequiredWS(), middleware.AuthRequired()),
		privilegedPluginHTTP,
		whenPrivileged(middleware.RequireInteractiveUser()),
		whenPrivileged(middleware.RequireSecureSession()),
		whenPrivileged(middleware.RejectInDemo()),
		middleware.ForWebSocketUpgrade(middleware.ProxyWs(), middleware.Proxy()),
		capability.NewHTTPHandler(plugin.GetManager()),
	)
}

// privilegedPluginHTTP runs before proxying so local-only privileged management
// cannot be delegated through a node selection header.
func privilegedPluginHTTP(c *gin.Context) {
	if !plugin.GetManager().PrivilegedHTTP(c.Param("id")) {
		c.Next()
		return
	}
	_, proxySelected := c.Get("ProxyNodeID")
	if c.GetHeader("X-Node-ID") != "" || proxySelected {
		c.AbortWithStatusJSON(403, gin.H{"message": "Privileged plugin APIs are local-only"})
		return
	}
	c.Next()
}

func whenPrivileged(handler gin.HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		if plugin.GetManager().PrivilegedHTTP(c.Param("id")) {
			handler(c)
		} else {
			c.Next()
		}
	}
}
