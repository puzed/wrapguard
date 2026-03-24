package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReleaseWorkflowPackagesExpectedMacOSArtifacts(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatalf("failed to read release workflow: %v", err)
	}

	content := string(data)
	requiredSnippets := []string{
		`archive="wrapguard-${{ github.event.release.tag_name }}-darwin-${{ matrix.arch }}.tar.gz"`,
		`wrapguard libwrapguard.dylib`,
		`test -f "$verify_dir/libwrapguard.dylib"`,
		`name: Verify macOS release archives`,
		`uses: actions/download-artifact@v4`,
		`needs: verify-macos-release-archives`,
		`asset_name: wrapguard-${{ github.event.release.tag_name }}-darwin-${{ matrix.arch }}.tar.gz`,
	}

	for _, snippet := range requiredSnippets {
		if !strings.Contains(content, snippet) {
			t.Fatalf("release workflow missing required macOS archive snippet: %q", snippet)
		}
	}
}

func TestReleaseWorkflowValidatesLinuxArm64ArchivesWithoutExecutingBinary(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatalf("failed to read release workflow: %v", err)
	}

	content := string(data)
	requiredSnippets := []string{
		`archive="wrapguard-${{ github.event.release.tag_name }}-linux-${{ matrix.arch }}.tar.gz"`,
		`if [ "${{ matrix.arch }}" = "amd64" ]; then`,
		`"$verify_dir/wrapguard" --version`,
		`"$verify_dir/wrapguard" --help`,
		`file "$verify_dir/wrapguard" | grep -qi "aarch64\\|arm64"`,
	}

	for _, snippet := range requiredSnippets {
		if !strings.Contains(content, snippet) {
			t.Fatalf("release workflow missing required Linux validation snippet: %q", snippet)
		}
	}

	forbiddenSnippet := `if [ "${{ matrix.arch }}" = "arm64" ]; then
          "$verify_dir/wrapguard" --version`
	if strings.Contains(content, forbiddenSnippet) {
		t.Fatalf("release workflow should not execute the Linux arm64 binary during archive validation")
	}
}

func TestSmokeMacOSTargetValidatesExpectedRuntimeArtifacts(t *testing.T) {
	data, err := os.ReadFile("Makefile")
	if err != nil {
		t.Fatalf("failed to read Makefile: %v", err)
	}

	content := string(data)
	requiredSnippets := []string{
		`cp "$(DIST_DIR)/darwin-$(TARGET_GOARCH)/$(BINARY_NAME)" "$$package_dir/";`,
		`cp "$(DIST_DIR)/darwin-$(TARGET_GOARCH)/$(LIBRARY_NAME)" "$$package_dir/";`,
		`tar -C "$$package_dir" -czf "$$staging/$(BINARY_NAME)-macos-smoke.tar.gz" $(BINARY_NAME) $(LIBRARY_NAME) README.md example-wg0.conf;`,
		`test -f "$$verify_dir/$(LIBRARY_NAME)";`,
		`build-macos-universal`,
		`lipo -create "$$stage_dir/amd64/$(BINARY_NAME)" "$$stage_dir/arm64/$(BINARY_NAME)" -output "$$final_dir/$(BINARY_NAME)";`,
	}

	for _, snippet := range requiredSnippets {
		if !strings.Contains(content, snippet) {
			t.Fatalf("Makefile missing required macOS smoke packaging snippet: %q", snippet)
		}
	}
}

func TestMacOSReleaseNotesTemplateDocumentsSupportMatrix(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("docs", "release-notes-macos.md"))
	if err != nil {
		t.Fatalf("failed to read macOS release notes template: %v", err)
	}

	content := string(data)
	requiredSnippets := []string{
		`## Support Matrix`,
		`macOS 14 Sonoma`,
		`macOS 15 Sequoia`,
		`## Known Limitations`,
		`## Example Commands`,
	}

	for _, snippet := range requiredSnippets {
		if !strings.Contains(content, snippet) {
			t.Fatalf("release notes template missing required snippet: %q", snippet)
		}
	}
}
