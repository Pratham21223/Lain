package diff

import (
	"lain/internal/loader"
	"lain/internal/types"
)

func LoadSnapshot(path string) ([]types.Route, error) {
	return loader.LoadRoutes(path)
}

func sameParams(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	set := make(map[string]bool, len(a))
	for _, p := range a {
		set[p] = true
	}
	for _, p := range b {
		if !set[p] {
			return false
		}
	}
	return true
}

func DiffRoutes(base, head []types.Route) (added []types.Route, changed []types.Route, unchanged []types.Route) {
	key := func(r types.Route) string {
		return r.Method + " " + r.Path
	}

	baseByKey := make(map[string]types.Route, len(base))
	for _, r := range base {
		baseByKey[key(r)] = r
	}

	for _, r := range head {
		b, ok := baseByKey[key(r)]
		if !ok {
			added = append(added, r)
			continue
		}
		if sameParams(b.Params, r.Params) {
			unchanged = append(unchanged, r)
		} else {
			changed = append(changed, r)
		}
	}

	return added, changed, unchanged
}
