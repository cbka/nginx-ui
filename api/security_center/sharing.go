package security_center

import "github.com/gin-gonic/gin"

func GetSharing(c *gin.Context) { c.JSON(200, manager().Sharing()) }
func PutSharing(c *gin.Context) {
	var p struct {
		Enabled *bool `json:"enabled"`
	}
	if !bind(c, &p) {
		return
	}
	if p.Enabled == nil {
		c.JSON(400, gin.H{"message": "enabled must be an explicit boolean"})
		return
	}
	if err := manager().SetSharing(c.Request.Context(), *p.Enabled); err != nil {
		fail(c, err)
		return
	}
	v := manager().Sharing()
	c.JSON(200, gin.H{"configured": v.Configured, "enabled": v.Enabled, "runtime_verified": false, "editable": v.Editable, "applied": true, "message": "Engine configuration saved and validated; reload hook completed. Live sharing state is not verified"})
}
