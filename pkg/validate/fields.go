package validate

import (
	"fmt"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
)

type Key uint32

func ValidateFields(data *framework.FieldData, valid []string) error {
	mapKeys := []string{}
	for key := range data.Raw {
		mapKeys = append(mapKeys, key)
	}

	invalidKeys := []string{}

	for _, key := range mapKeys {
		found := false
		for _, validKey := range valid {
			if key == validKey {
				found = true
				break
			}
		}
		if !found {
			invalidKeys = append(invalidKeys, key)
		}
	}

	if len(invalidKeys) > 0 {
		return fmt.Errorf("invalid keys: % #v", strings.Join(invalidKeys, ", "))
	}
	return nil
}
