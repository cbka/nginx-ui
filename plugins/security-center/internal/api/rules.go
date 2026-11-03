package security_center

import "github.com/gin-gonic/gin"

func Rules(c *gin.Context) {
	rules, err := manager().Rules(c.Request.Context())
	if err != nil {
		fail(c, err)
		return
	}
	c.JSON(200, rules)
}
