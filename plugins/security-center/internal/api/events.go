package security_center

import (
	"github.com/gin-gonic/gin"
	"strconv"
)

func Events(c *gin.Context) {
	limit, err := strconv.Atoi(c.DefaultQuery("limit", "100"))
	if err != nil {
		c.JSON(400, gin.H{"message": "Invalid event limit"})
		return
	}
	result, err := manager().EventsForRequest(c.Request.Context(), c.Query("source"), c.Query("vhost"), c.DefaultQuery("since", "1h"), limit, c.Query("node"), c.Query("request_id"))
	if err != nil {
		fail(c, err)
		return
	}
	c.JSON(200, result)
}
