package plugin

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"time"

	"github.com/0xJacky/Nginx-UI/internal/nodeauth"
	plugin "github.com/0xJacky/Nginx-UI/internal/plugin"
	"github.com/0xJacky/Nginx-UI/internal/plugin/jsonrpc"
	"github.com/0xJacky/Nginx-UI/internal/plugin/protocol"
	"github.com/0xJacky/Nginx-UI/model"
	"github.com/gin-gonic/gin"
)

type replicaHost interface {
	Get(string) (*plugin.Info, error)
	Acquire(context.Context, string) (jsonrpc.Caller, func(), error)
}

// InitReplicaRouter belongs to the authenticated LOCAL group, never Proxy.
func InitReplicaRouter(r *gin.RouterGroup) {
	r.PUT("/plugins/:id/replica/sites/:name", requireReplicaController, func(c *gin.Context) { servePluginReplica(plugin.GetManager(), c) })
}

func requireReplicaController(c *gin.Context) {
	value, ok := c.Get(nodeauth.GinPrincipalKey)
	p, valid := value.(*nodeauth.Principal)
	if !ok || !valid || p == nil || p.AuthMethod != model.NodeAuthMethodPaired || p.ControllerInstanceID == "" {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"message": "A verified paired controller is required"})
		return
	}
	c.Next()
}

func servePluginReplica(host replicaHost, c *gin.Context) {
	id := c.Param("id")
	if !plugin.IsValidID(id) {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}
	info, err := host.Get(id)
	if err != nil || !info.Enabled || !slices.Contains(info.Permissions, protocol.PermissionClusterSync) {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(c.Writer, c.Request.Body, plugin.MaxClusterPayloadBytes))
	if err != nil {
		c.AbortWithStatus(http.StatusRequestEntityTooLarge)
		return
	}
	name := c.Param("name")
	if err = plugin.ValidateClusterSiteParams(protocol.HostClusterSiteSyncParams{Name: name, Payload: raw}); err != nil {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}
	principal := c.MustGet(nodeauth.GinPrincipalKey).(*nodeauth.Principal)
	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()
	caller, release, err := host.Acquire(ctx, id)
	if release != nil {
		defer release()
	}
	if err != nil {
		c.AbortWithStatus(http.StatusServiceUnavailable)
		return
	}
	var result json.RawMessage
	err = caller.Call(ctx, protocol.MethodClusterSiteApply, protocol.ClusterSiteApplyParams{Name: name, Payload: raw, ControllerInstanceID: principal.ControllerInstanceID}, &result)
	if err != nil {
		c.JSON(http.StatusConflict, gin.H{"message": "Plugin rejected the replicated operation"})
		return
	}
	if len(result) > 65536 || !json.Valid(result) {
		c.AbortWithStatus(http.StatusBadGateway)
		return
	}
	c.Data(http.StatusOK, "application/json", result)
}
