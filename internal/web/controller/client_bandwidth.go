package controller

import (
	"encoding/json/v2"
	"errors"

	"github.com/gin-gonic/gin"
	"github.com/mhsanaei/3x-ui/v3/internal/bandwidthruntime"
	"github.com/mhsanaei/3x-ui/v3/internal/web/service"
)

func (a *ClientController) getBandwidth(c *gin.Context) {
	settings, err := (service.ClientBandwidthService{}).Get(c.Request.Context(), a.bandwidth, c.Param("email"))
	jsonObj(c, settings, err)
}

func (a *ClientController) setBandwidth(c *gin.Context) {
	var req struct {
		TotalBitsPerSecond *int64            `json:"totalBitsPerSecond"`
		NodeBitsPerSecond  map[string]*int64 `json:"nodeBitsPerSecond"`
	}
	if err := json.UnmarshalRead(c.Request.Body, &req, json.RejectUnknownMembers(true)); err != nil || req.TotalBitsPerSecond == nil || req.NodeBitsPerSecond == nil {
		jsonObj(c, nil, errors.New("totalBitsPerSecond and nodeBitsPerSecond must be provided as an integer and an object"))
		return
	}
	nodeRates := make(map[string]int64, len(req.NodeBitsPerSecond))
	for key, rate := range req.NodeBitsPerSecond {
		if rate == nil {
			jsonObj(c, nil, errors.New("bandwidth node limit must be an integer"))
			return
		}
		nodeRates[key] = *rate
	}
	policy := bandwidthruntime.ClientBandwidthPolicy{TotalBitsPerSecond: *req.TotalBitsPerSecond, NodeBitsPerSecond: nodeRates}
	settings, err := (service.ClientBandwidthService{}).Save(c.Request.Context(), a.bandwidth, c.Param("email"), policy)
	jsonObj(c, settings, err)
}
