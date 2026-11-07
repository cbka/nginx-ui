package security_center

import (
	"github.com/gin-gonic/gin"
)

// InitRouter is local-only: no remote-node proxy can delegate these privileged
// management actions. The parent router must require authentication.
func InitRouter(parent *gin.RouterGroup) {
	g := parent.Group("/security-center")
	g.GET("/status", Status)
	g.GET("/templates", Templates)
	g.PUT("/templates/:id", PutTemplate)
	g.DELETE("/templates/:id", DeleteTemplate)
	g.GET("/crowdsec/sharing", GetSharing)
	g.PUT("/crowdsec/sharing", PutSharing)
	g.GET("/crowdsec/decisions", Decisions)
	g.POST("/crowdsec/decisions", AddDecision)
	g.DELETE("/crowdsec/decisions/:id", DeleteDecision)
	g.GET("/crowdsec/appsec", AppSec)
	g.POST("/crowdsec/appsec/rules", ChangeAppSecRule)
	g.GET("/crowdsec/bulk/preview", BulkPreview)
	g.POST("/crowdsec/bulk/jobs", BulkStart)
	g.GET("/crowdsec/bulk/jobs/:id", BulkStatus)
	g.GET("/crowdsec/scenarios", Scenarios)
	g.POST("/crowdsec/scenarios", ChangeScenario)
	g.GET("/modsecurity/rules", Rules)
	g.GET("/events", Events)
	g.GET("/sites", Sites)
	g.GET("/sites/:name", GetSite)
	g.PUT("/sites/:name", PutSite)
	g.POST("/sites/:name/sync", SyncSite)
	g.GET("/modsecurity", GetModSecurity)
	g.PUT("/modsecurity", PutModSecurity)
}
