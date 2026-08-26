package loader

import (
	"encoding/json"
	"os"

	"lain/internal/types"
)

func LoadRoutes(path string) ([]types.Route, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var routes []types.Route
	if err := json.Unmarshal(data, &routes); err != nil {
		return nil, err
	}
	return routes, nil
}
