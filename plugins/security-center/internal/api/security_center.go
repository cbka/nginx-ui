package security_center

import (
	"errors"
	"net/http"
	"os"
	"strings"

	center "github.com/0xJacky/Nginx-UI/plugins/security-center/internal/center"
	"github.com/gin-gonic/gin"
)

var service *center.Service

func SetService(s *center.Service) { service = s }
func manager() *center.Service     { return service }
func fail(c *gin.Context, err error) {
	code := http.StatusBadGateway
	if errors.Is(err, center.ErrDisabled) {
		code = http.StatusServiceUnavailable
	} else if errors.Is(err, center.ErrInvalid) {
		code = http.StatusBadRequest
	}
	c.JSON(code, gin.H{"message": err.Error()})
}
func bind(c *gin.Context, v any) bool {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 131072)
	if err := c.ShouldBindJSON(v); err != nil {
		c.JSON(400, gin.H{"message": "Invalid security request"})
		return false
	}
	return true
}
func Status(c *gin.Context) {
	s := manager()
	c.JSON(200, gin.H{"enabled": s.Config.Enabled, "appsec_enabled": s.Config.Enabled && s.Config.CrowdSecEnabled && s.Config.AppSecEnabled, "crowdsec_enabled": s.Config.Enabled && s.Config.CrowdSecEnabled, "modsecurity_enabled": s.Config.Enabled && s.Config.ModSecurityEnabled, "events_configured": s.Config.Enabled && strings.TrimSpace(os.Getenv("SECURITY_CENTER_LOKI_URL")) != "", "scenario_changes_enabled": s.Config.Enabled && s.Config.CrowdSecEnabled && s.Config.CrowdSecReloadPath != "", "runtime_integration_verified": s.RuntimeReady(c.Request.Context())})
}
func Decisions(c *gin.Context) {
	b, err := manager().List(c.Request.Context(), "decisions")
	if err != nil {
		fail(c, err)
		return
	}
	c.JSON(200, gin.H{"items": b, "limited": true, "alert_limit": 100, "includes_central_api": false, "includes_simulated": false})
}
func AddDecision(c *gin.Context) {
	var d center.Decision
	if !bind(c, &d) {
		return
	}
	if err := manager().AddDecision(c.Request.Context(), d); err != nil {
		fail(c, err)
		return
	}
	c.JSON(200, gin.H{"message": "Ban added", "applied": true})
}
func DeleteDecision(c *gin.Context) {
	if err := manager().DeleteDecision(c.Request.Context(), c.Param("id")); err != nil {
		fail(c, err)
		return
	}
	c.JSON(200, gin.H{"message": "Decision removed", "applied": true})
}
func Scenarios(c *gin.Context) {
	b, err := manager().List(c.Request.Context(), "scenarios")
	if err != nil {
		fail(c, err)
		return
	}
	c.JSON(200, gin.H{"items": b})
}
func ChangeScenario(c *gin.Context) {
	var p struct {
		Name   string `json:"name"`
		Action string `json:"action"`
	}
	if !bind(c, &p) {
		return
	}
	if err := manager().Scenario(c.Request.Context(), p.Name, p.Action); err != nil {
		fail(c, err)
		return
	}
	c.JSON(200, gin.H{"message": "Scenario updated and engine reload completed", "applied": true})
}
func GetModSecurity(c *gin.Context) {
	v, err := manager().ReadWAF()
	if err != nil {
		fail(c, err)
		return
	}
	c.JSON(200, v)
}
func PutModSecurity(c *gin.Context) {
	var p center.WAFConfig
	if !bind(c, &p) {
		return
	}
	if err := manager().ApplyWAF(c.Request.Context(), p); err != nil {
		fail(c, err)
		return
	}
	c.JSON(200, gin.H{"message": "Global defaults saved; managed local sites validated and reload requested when applicable", "applied": true})
}

func Sites(c *gin.Context) {
	v, err := manager().Sites()
	if err != nil {
		fail(c, err)
		return
	}
	c.JSON(200, gin.H{"items": v})
}
func GetSite(c *gin.Context) {
	v, err := manager().GetSite(c.Param("name"))
	if err != nil {
		fail(c, err)
		return
	}
	c.JSON(200, v)
}
func PutSite(c *gin.Context) {
	var p center.SitePolicy
	if !bind(c, &p) {
		return
	}
	v, err := manager().ApplySite(c.Request.Context(), c.Param("name"), p)
	if err != nil {
		fail(c, err)
		return
	}
	c.JSON(200, gin.H{"name": v.Name, "policy": v.Policy, "effective": v.Effective, "applied": true, "message": "Local policy saved; Nginx configuration validated and reload requested. Disabled sites remain inactive; peer rollout is not implied"})
}

func AppSec(c *gin.Context) {
	b, err := manager().AppSecInventory(c.Request.Context())
	if err != nil {
		fail(c, err)
		return
	}
	c.Data(200, "application/json", b)
}
