package security_center

import "github.com/gin-gonic/gin"

func BulkPreview(c *gin.Context) {
	b, err := manager().BulkPreview(c.Request.Context(), c.Query("kind"))
	if err != nil {
		fail(c, err)
		return
	}
	c.Data(200, "application/json", b)
}
func BulkStart(c *gin.Context) {
	var p struct {
		Kind      string `json:"kind"`
		PreviewID string `json:"preview_id"`
	}
	if !bind(c, &p) {
		return
	}
	b, err := manager().BulkStart(c.Request.Context(), p.Kind, p.PreviewID)
	if err != nil {
		fail(c, err)
		return
	}
	c.Data(202, "application/json", b)
}
func BulkStatus(c *gin.Context) {
	b, err := manager().BulkStatus(c.Request.Context(), c.Param("id"))
	if err != nil {
		fail(c, err)
		return
	}
	c.Data(200, "application/json", b)
}
