package security_center

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/0xJacky/Nginx-UI/internal/nodeauth"
	center "github.com/0xJacky/Nginx-UI/internal/security_center"
	"github.com/0xJacky/Nginx-UI/internal/site"
	"github.com/0xJacky/Nginx-UI/model"
	"github.com/gin-gonic/gin"
	"github.com/go-resty/resty/v2"
)

func requirePairedController(c *gin.Context) {
	value, ok := c.Get(nodeauth.GinPrincipalKey)
	p, valid := value.(*nodeauth.Principal)
	if !ok || !valid || p == nil || p.AuthMethod != model.NodeAuthMethodPaired || p.ControllerInstanceID == "" {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"message": "A verified paired controller is required"})
		return
	}
	c.Next()
}
func ApplyReplica(c *gin.Context) {
	var p center.ReplicaPayload
	if !bind(c, &p) {
		return
	}
	if p.Name != c.Param("name") {
		fail(c, center.ErrInvalid)
		return
	}
	principal := c.MustGet(nodeauth.GinPrincipalKey).(*nodeauth.Principal)
	changed, err := manager().ApplyReplica(c.Request.Context(), p, principal.ControllerInstanceID)
	if err != nil {
		fail(c, err)
		return
	}
	status := "unchanged"
	if changed {
		status = "applied"
	}
	c.JSON(200, gin.H{"status": status, "revision": strconv.FormatInt(p.Revision, 10), "message": "Site snapshot applied locally; no onward replication"})
}

type peerResult struct {
	NodeID   uint64 `json:"node_id"`
	Node     string `json:"node"`
	Status   string `json:"status"`
	Message  string `json:"message"`
	Revision string `json:"revision"`
}

// SyncSite uses only the existing site/namespace membership, never caller URLs.
// Each peer commits or rolls back independently; this is not a cluster transaction.
func SyncSite(c *gin.Context) {
	payload, err := manager().ExportSite(c.Param("name"))
	if err != nil {
		fail(c, err)
		return
	}
	nodes := site.GetSyncNodes(payload.Name)
	if len(nodes) > 32 {
		c.JSON(400, gin.H{"message": "Security sync is limited to 32 configured peers"})
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 60*time.Second)
	defer cancel()
	results := make([]peerResult, len(nodes))
	semaphore := make(chan struct{}, 2)
	var wg sync.WaitGroup
	for i, node := range nodes {
		wg.Add(1)
		go func(i int, node *model.Node) {
			defer wg.Done()
			result := peerResult{NodeID: node.ID, Node: node.Name, Status: "failed", Revision: strconv.FormatInt(payload.Revision, 10)}
			defer func() { results[i] = result }()
			if !node.Enabled || node.AuthMethod != model.NodeAuthMethodPaired || !node.HasCredential() {
				result.Status = "unsupported"
				result.Message = "Peer must be enabled and paired with active credentials"
				return
			}
			select {
			case semaphore <- struct{}{}:
				defer func() { <-semaphore }()
			case <-ctx.Done():
				result.Message = "Sync time budget exhausted"
				return
			}
			client := nodeauth.NewRestyClient(node).SetBaseURL(node.URL).SetTimeout(30 * time.Second).SetResponseBodyLimit(65536).SetRedirectPolicy(resty.NoRedirectPolicy())
			var body struct {
				Status   string `json:"status"`
				Revision string `json:"revision"`
			}
			response, err := client.R().SetContext(ctx).SetBody(payload).SetResult(&body).Put("/api/security-center/replica/sites/" + url.PathEscape(payload.Name))
			if err != nil {
				result.Message = "Peer request failed or timed out"
				return
			}
			if response.StatusCode() == 404 {
				result.Status = "unsupported"
				result.Message = "Peer does not support security policy replication"
				return
			}
			if response.StatusCode() != http.StatusOK {
				result.Message = "Peer rejected policy (HTTP " + strconv.Itoa(response.StatusCode()) + ")"
				return
			}
			if body.Revision != result.Revision || (body.Status != "applied" && body.Status != "unchanged") {
				result.Message = "Peer returned an invalid acknowledgement"
				return
			}
			result.Status = body.Status
			result.Message = "Peer confirmed this revision"
		}(i, node)
	}
	wg.Wait()
	c.JSON(200, gin.H{"results": results, "revision": strconv.FormatInt(payload.Revision, 10), "atomic": false, "message": "Each peer result is independent; failed peers retain their prior configuration"})
}
