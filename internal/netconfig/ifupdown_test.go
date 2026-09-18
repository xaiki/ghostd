package netconfig

import (
	"strings"
	"testing"
)

func TestIfupdownBootPersistence(t *testing.T) {
	path := InterfacesDir + "/stack-eth0.conf"
	content := "auto eth0\niface eth0 inet static\n address 192.0.2.2/24\n"
	desired := map[string]string{path: content}
	for _, tc := range []struct{ name, main, oldPath, oldContent, want string }{
		{"included", "source /etc/network/interfaces.d/*\n", "", "", ""},
		{"idempotent", "source /etc/network/interfaces.d/*\n", path, content, ""},
		{"legacy duplicate", "source /etc/network/interfaces.d/*\n", InterfacesDir + "/eth0", content, "duplicate"},
		{"backup included", "source /etc/network/interfaces.d/*\n", InterfacesDir + "/eth0~", content, "duplicate"},
		{"dot filename excluded", "source-directory /etc/network/interfaces.d\n", "", "", "not loaded at boot"},
		{"no include", "iface lo inet loopback\n", "", "", "not loaded at boot"},
		{"duplicate include", "source /etc/network/interfaces.d/*\nsource /etc/network/interfaces.d/stack-*.conf\n", "", "", "duplicate"},
		{"ipv6 lost", "source /etc/network/interfaces.d/*\n", path, content + "iface eth0 inet6 static\n address fd00::1/64\n", "remove boot configuration"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			current := map[string]string{interfacesMain: tc.main}
			if tc.oldPath != "" {
				current[tc.oldPath] = tc.oldContent
			}
			err := checkIfupdownFiles(current, desired)
			if tc.want == "" && err != nil {
				t.Fatal(err)
			}
			if tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
				t.Fatalf("want %s, got %v", tc.want, err)
			}
		})
	}
}
