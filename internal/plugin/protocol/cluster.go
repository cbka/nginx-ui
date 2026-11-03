package protocol

import "encoding/json"

const (
	PermissionClusterSync     = "cluster.sync"
	MethodHostClusterSiteSync = "host.cluster.site_sync"
	MethodClusterSiteApply    = "cluster.site.apply"
)

// The host supplies authenticated controller identity; it never comes from payload.
type ClusterSiteApplyParams struct {
	Name                 string          `json:"name"`
	Payload              json.RawMessage `json:"payload"`
	ControllerInstanceID string          `json:"controller_instance_id"`
}
type HostClusterSiteSyncParams struct {
	Name    string          `json:"name"`
	Payload json.RawMessage `json:"payload"`
}
type ClusterPeerResult struct {
	NodeID   uint64          `json:"node_id"`
	Node     string          `json:"node"`
	Status   string          `json:"status"`
	Message  string          `json:"message"`
	Response json.RawMessage `json:"response,omitempty"`
}
type HostClusterSiteSyncResult struct {
	Results []ClusterPeerResult `json:"results"`
	Atomic  bool                `json:"atomic"`
}
