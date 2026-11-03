package security_center

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type CRSRule struct {
	ID      int    `json:"id"`
	Message string `json:"message"`
	File    string `json:"file"`
}
type RuleCatalog struct {
	Items     []CRSRule `json:"items"`
	Truncated bool      `json:"truncated"`
}

var crsID = regexp.MustCompile(`\bid\s*:\s*'?([0-9]{6})'?`)
var crsMessage = regexp.MustCompile(`\bmsg\s*:\s*'([^'\r\n]{0,512})'`)

// Rules reads only the configured CRS files. It never accepts browser filesystem paths.
func (s *Service) Rules(ctx context.Context) (RuleCatalog, error) {
	result := RuleCatalog{Items: []CRSRule{}}
	if err := s.waf(); err != nil {
		return result, err
	}
	if !filepath.IsAbs(s.Config.CRSRules) {
		return result, ErrInvalid
	}
	files, err := filepath.Glob(s.Config.CRSRules)
	if err != nil {
		return result, ErrInvalid
	}
	if len(files) > 256 {
		return result, fmt.Errorf("CRS catalog file limit exceeded")
	}
	seen := map[int]bool{}
	total := int64(0)
	for _, path := range files {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		info, err := os.Lstat(path)
		if err != nil {
			return result, err
		}
		if !info.Mode().IsRegular() || info.Size() > 2<<20 {
			return result, fmt.Errorf("invalid CRS catalog file")
		}
		total += info.Size()
		if total > 16<<20 {
			return result, fmt.Errorf("CRS catalog size limit exceeded")
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return result, err
		}
		// Join continuation lines before extracting the rule's action list.
		logical := strings.ReplaceAll(string(data), "\\\r\n", " ")
		logical = strings.ReplaceAll(logical, "\\\n", " ")
		for _, line := range strings.Split(logical, "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "SecRule ") && !strings.HasPrefix(line, "SecAction ") {
				continue
			}
			idMatch := crsID.FindStringSubmatch(line)
			if len(idMatch) != 2 {
				continue
			}
			id, _ := strconv.Atoi(idMatch[1])
			if id < 900000 || seen[id] {
				continue
			}
			message := ""
			if match := crsMessage.FindStringSubmatch(line); len(match) == 2 {
				message = match[1]
			}
			if len(result.Items) == 2000 {
				result.Truncated = true
				break
			}
			seen[id] = true
			result.Items = append(result.Items, CRSRule{id, message, filepath.Base(path)})
		}
	}
	sort.Slice(result.Items, func(i, j int) bool { return result.Items[i].ID < result.Items[j].ID })
	return result, nil
}
