package security_center

import (
	center "github.com/0xJacky/Nginx-UI/plugins/security-center/internal/center"
	"github.com/gin-gonic/gin"
)

func Templates(c *gin.Context) {
	items, err := manager().Templates()
	if err != nil {
		fail(c, err)
		return
	}
	c.JSON(200, gin.H{"items": items})
}
func PutTemplate(c *gin.Context) {
	var p struct {
		Name        string            `json:"name"`
		Description string            `json:"description"`
		Policy      center.SitePolicy `json:"policy"`
	}
	if !bind(c, &p) {
		return
	}
	t := center.PolicyTemplate{ID: c.Param("id"), Name: p.Name, Description: p.Description, Policy: p.Policy}
	if err := manager().SaveTemplate(t); err != nil {
		fail(c, err)
		return
	}
	c.JSON(200, gin.H{"item": t, "applied": false, "message": "Template saved; no website configuration changed"})
}
func DeleteTemplate(c *gin.Context) {
	if err := manager().DeleteTemplate(c.Param("id")); err != nil {
		fail(c, err)
		return
	}
	c.JSON(200, gin.H{"applied": false, "message": "Template removed; existing website policies remain unchanged"})
}
