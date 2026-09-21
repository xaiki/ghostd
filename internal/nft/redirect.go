package nft

import (
	"encoding/json"
	"fmt"
)

// ValidateRedirectCoexistence prevents a narrow redirect request from erasing
// an existing ghostd filtering policy. Tables owned by other services remain intact.
func ValidateRedirectCoexistence(raw []byte) error {
	var document struct {
		Objects []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		return err
	}
	for _, object := range document.Objects {
		if value, ok := object["chain"]; ok {
			var chain struct{ Family, Table, Type string }
			if err := json.Unmarshal(value, &chain); err != nil {
				return err
			}
			if chain.Family == "inet" && chain.Table == tableName && chain.Type == "filter" {
				return fmt.Errorf("nft: redirect-only policy would remove existing ghostd filtering; retain the declared full firewall policy")
			}
		}
	}
	return nil
}
