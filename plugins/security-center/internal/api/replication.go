package security_center

import (
	"context"
	"encoding/json"
	"github.com/0xJacky/Nginx-UI/internal/plugin/protocol"
	center "github.com/0xJacky/Nginx-UI/plugins/security-center/internal/center"
	"github.com/gin-gonic/gin"
	"strconv"
	"time"
)

var HostCall func(context.Context, string, any, any) error

func SyncSite(c *gin.Context) {
	payload, err := manager().ExportSite(c.Param("name"))
	if err != nil {
		fail(c, err)
		return
	}
	b, _ := json.Marshal(payload)
	ctx, cancel := context.WithTimeout(c.Request.Context(), 65*time.Second)
	defer cancel()
	var response protocol.HostClusterSiteSyncResult
	if err = HostCall(ctx, protocol.MethodHostClusterSiteSync, protocol.HostClusterSiteSyncParams{Name: payload.Name, Payload: b}, &response); err != nil {
		fail(c, err)
		return
	}
	rev := strconv.FormatInt(payload.Revision, 10)
	results := make([]map[string]any, 0, len(response.Results))
	for _, peer := range response.Results {
		status, message := peer.Status, peer.Message
		if status == "received" {
			var ack struct {
				Status   string `json:"status"`
				Revision string `json:"revision"`
			}
			if json.Unmarshal(peer.Response, &ack) != nil || ack.Revision != rev || (ack.Status != "applied" && ack.Status != "unchanged") {
				status = "failed"
				message = "Peer returned an invalid acknowledgement"
			} else {
				status = ack.Status
				message = "Peer confirmed this revision"
			}
		}
		results = append(results, map[string]any{"node_id": peer.NodeID, "node": peer.Node, "status": status, "message": message, "revision": rev})
	}
	c.JSON(200, gin.H{"results": results, "revision": rev, "atomic": false, "message": "Each peer result is independent; failed peers retain their prior configuration"})
}
func ApplyReplica(ctx context.Context, raw json.RawMessage) (any, error) {
	var request protocol.ClusterSiteApplyParams
	if err := json.Unmarshal(raw, &request); err != nil {
		return nil, center.ErrInvalid
	}
	var p center.ReplicaPayload
	if json.Unmarshal(request.Payload, &p) != nil || p.Name != request.Name {
		return nil, center.ErrInvalid
	}
	changed, err := manager().ApplyReplica(ctx, p, request.ControllerInstanceID)
	if err != nil {
		return nil, err
	}
	status := "unchanged"
	if changed {
		status = "applied"
	}
	return map[string]string{"status": status, "revision": strconv.FormatInt(p.Revision, 10)}, nil
}
