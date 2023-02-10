// Package stm provides methods for converting a golang struct to a map[string]interface{} and vice versa using JSON tags
// Therefore the name: stm -> *S*truct *T*o *M*ap
package stm

import "encoding/json"

func StructToMap[T any](in *T, out *map[string]interface{}) error {
	// convert struct to json
	jsonBytes, err := json.Marshal(in)
	if err != nil {
		return err
	}
	// convert json to map
	if err := json.Unmarshal(jsonBytes, &out); err != nil {
		return err
	}

	return nil
}

func MapToStruct[T any](in map[string]interface{}, out *T) error {
	// convert map to json
	jsonBytes, err := json.Marshal(in)
	if err != nil {
		return err
	}
	// convert json to struct
	if err := json.Unmarshal(jsonBytes, out); err != nil {
		return err
	}

	return nil
}
