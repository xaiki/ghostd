package netconfig

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const interfacesMain = "/etc/network/interfaces"

// Verify the boot include tree, not just the files this apply happens to own.
// This deliberately refuses ambiguity rather than selecting a duplicate stanza.
func checkIfupdownFiles(current, desired map[string]string) error {
	generated := map[string]bool{}
	files := map[string]string{}
	for p, s := range current {
		files[p] = s
	}
	for p, s := range desired {
		files[p] = s
		if strings.HasPrefix(p, InterfacesDir+"/") {
			generated[p] = true
		}
	}
	if len(generated) == 0 {
		return nil
	}
	reached, active := map[string]bool{}, map[string]bool{}
	claims := map[string]string{}
	directoryName := regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	var visit func(string) error
	visit = func(path string) error {
		if active[path] {
			return fmt.Errorf("ifupdown include cycle: %s", path)
		}
		content, ok := files[path]
		if !ok {
			return fmt.Errorf("ifupdown file was not captured: %s", path)
		}
		active[path], reached[path] = true, true
		defer delete(active, path)
		for _, line := range strings.Split(content, "\n") {
			words := strings.Fields(strings.SplitN(line, "#", 2)[0])
			if len(words) == 0 {
				continue
			}
			if words[0] == "iface" && len(words) >= 4 {
				key := words[1] + " " + words[2]
				if prior, ok := claims[key]; ok {
					return fmt.Errorf("duplicate ifupdown definition %s: %s and %s", key, prior, path)
				}
				claims[key] = path
			}
			if words[0] != "source" && words[0] != "source-directory" {
				continue
			}
			for _, pattern := range words[1:] {
				if !filepath.IsAbs(pattern) {
					pattern = filepath.Join(filepath.Dir(path), pattern)
				}
				includeDir := filepath.Dir(pattern)
				if words[0] == "source-directory" {
					includeDir = pattern
				}
				if includeDir != InterfacesDir {
					return fmt.Errorf("ifupdown include directory is not fully captured: %s", includeDir)
				}
				found := false
				for _, p := range sortedKeys(files) {
					target := p
					if words[0] == "source-directory" {
						if !directoryName.MatchString(filepath.Base(p)) {
							continue
						}
						target = filepath.Dir(p)
					}
					match, err := filepath.Match(pattern, target)
					if err != nil {
						return fmt.Errorf("invalid ifupdown include %s: %w", pattern, err)
					}
					if match {
						found = true
						if err := visit(p); err != nil {
							return err
						}
					}
				}
				if words[0] == "source" && !found && !strings.ContainsAny(pattern, "*?[") {
					return fmt.Errorf("ifupdown include not captured: %s", pattern)
				}
			}
		}
		return nil
	}
	if err := visit(interfacesMain); err != nil {
		return err
	}
	for _, p := range sortedKeys(desired) {
		if generated[p] && !reached[p] {
			return fmt.Errorf("generated interface file is not loaded at boot: %s", p)
		}
		for _, line := range strings.Split(current[p], "\n") {
			words := strings.Fields(strings.SplitN(line, "#", 2)[0])
			if len(words) >= 4 && words[0] == "iface" && claims[words[1]+" "+words[2]] == "" {
				return fmt.Errorf("write would remove boot configuration for %s %s from %s", words[1], words[2], p)
			}
		}
	}
	return nil
}

func checkIfupdown(ds DesiredState) error {
	for path := range ds.Files {
		if strings.HasPrefix(path, InterfacesDir+"/") {
			current, err := readInterfacesFiles()
			if err != nil {
				return err
			}
			main, err := os.ReadFile(interfacesMain)
			if err != nil {
				return fmt.Errorf("read boot network configuration: %w", err)
			}
			current[interfacesMain] = string(main)
			return checkIfupdownFiles(current, ds.Files)
		}
	}
	return nil
}
