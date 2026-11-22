package model

// ClientBandwidth is managed independently of client sync and profile changes.
type ClientBandwidth struct {
	ClientID           int              `gorm:"column:client_id;primaryKey;autoIncrement:false"`
	TotalBitsPerSecond int64            `gorm:"not null"`
	NodeBitsPerSecond  map[string]int64 `gorm:"serializer:json;not null"`
}

func (ClientBandwidth) TableName() string { return "client_bandwidth" }
