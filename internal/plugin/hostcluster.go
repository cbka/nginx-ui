package plugin

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/0xJacky/Nginx-UI/internal/nodeauth"
	"github.com/0xJacky/Nginx-UI/internal/plugin/jsonrpc"
	"github.com/0xJacky/Nginx-UI/internal/plugin/protocol"
	"github.com/0xJacky/Nginx-UI/internal/site"
	"github.com/0xJacky/Nginx-UI/model"
	"github.com/go-resty/resty/v2"
)

const MaxClusterPayloadBytes = 1 << 20

type ClusterHostBackend interface {
	ClusterSiteSync(context.Context, string, protocol.HostClusterSiteSyncParams) (protocol.HostClusterSiteSyncResult, error)
}

// ValidateClusterSiteParams rejects traversal and bounds the opaque domain payload.
func ValidateClusterSiteParams(p protocol.HostClusterSiteSyncParams) error {
	if p.Name == "" || p.Name == "." || p.Name == ".." || len(p.Name) > 255 || strings.ContainsAny(p.Name, "/\\\x00\r\n") {
		return errors.New("invalid site name")
	}
	raw := strings.TrimSpace(string(p.Payload))
	if len(p.Payload) > MaxClusterPayloadBytes || len(raw) == 0 || raw[0] != '{' || !json.Valid(p.Payload) {
		return errors.New("site payload must be a JSON object within 1 MiB")
	}
	return nil
}

func registerClusterHostHandlers(conn *jsonrpc.Conn, pluginID string, granted []string, backend HostBackend) {
	conn.Handle(protocol.MethodHostClusterSiteSync, func(ctx context.Context, raw json.RawMessage) (any, error) {
		if err := requirePermission(granted, protocol.PermissionClusterSync); err != nil {
			return nil, err
		}
		var p protocol.HostClusterSiteSyncParams
		if err := decodeParams(raw, &p); err != nil {
			return nil, err
		}
		if err := ValidateClusterSiteParams(p); err != nil {
			return nil, jsonrpc.Errorf(protocol.CodeInvalidParams, err.Error())
		}
		b, ok := backend.(ClusterHostBackend)
		if !ok {
			return nil, errors.New("cluster site sync unavailable")
		}
		return b.ClusterSiteSync(ctx, pluginID, p)
	})
}

// Only configured site peers are contacted. The plugin cannot supply a URL,
// remote plugin ID, credential, or an arbitrary remote method.
func (b *hostBackend) ClusterSiteSync(ctx context.Context, pluginID string, p protocol.HostClusterSiteSyncParams) (protocol.HostClusterSiteSyncResult, error) {
	result := protocol.HostClusterSiteSyncResult{Results: []protocol.ClusterPeerResult{}}
	if !IsValidID(pluginID) {
		return result, errors.New("invalid plugin id")
	}
	if err := ValidateClusterSiteParams(p); err != nil {
		return result, err
	}
	nodes := site.GetSyncNodes(p.Name)
	if len(nodes) > 32 {
		return result, errors.New("site sync is limited to 32 configured peers")
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	result.Results = make([]protocol.ClusterPeerResult, len(nodes))
	slots := make(chan struct{}, 2)
	var wg sync.WaitGroup
	for i, node := range nodes {
		wg.Add(1)
		go func(i int, node *model.Node) {
			defer wg.Done()
			r := protocol.ClusterPeerResult{NodeID: node.ID, Node: node.Name, Status: "failed"}
			defer func() { result.Results[i] = r }()
			if !node.Enabled || node.AuthMethod != model.NodeAuthMethodPaired || !node.HasCredential() {
				r.Status = "unsupported"
				r.Message = "Peer must be enabled and paired with active credentials"
				return
			}
			select {
			case slots <- struct{}{}:
				defer func() { <-slots }()
			case <-ctx.Done():
				r.Message = "Sync time budget exhausted"
				return
			}
			client := nodeauth.NewRestyClient(node).SetBaseURL(node.URL).SetTimeout(30 * time.Second).SetResponseBodyLimit(65536).SetRedirectPolicy(resty.NoRedirectPolicy())
			response, err := client.R().SetContext(ctx).SetHeader("Content-Type", "application/json").SetBody([]byte(p.Payload)).Put("/api/plugins/" + url.PathEscape(pluginID) + "/replica/sites/" + url.PathEscape(p.Name))
			if err != nil {
				r.Message = "Peer request failed or timed out; state unknown"
				return
			}
			if response.StatusCode() == 404 {
				r.Status = "unsupported"
				r.Message = "Peer plugin is unavailable"
				return
			}
			if response.StatusCode() != http.StatusOK {
				r.Message = "Peer rejected the operation"
				return
			}
			if !json.Valid(response.Body()) {
				r.Message = "Peer acknowledgement was invalid"
				return
			}
			r.Status = "received"
			r.Message = "Peer returned acknowledgement; plugin must verify its revision"
			r.Response = append(json.RawMessage(nil), response.Body()...)
		}(i, node)
	}
	wg.Wait()
	return result, nil
}
