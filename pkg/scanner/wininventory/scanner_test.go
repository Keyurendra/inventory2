package wininventory

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	trivyTypes "github.com/aquasecurity/trivy/pkg/types"

	"github.com/accuknox/omniscan/pkg/scanner"
	"github.com/accuknox/omniscan/pkg/scanner/aiagent"
	trivyScanner "github.com/accuknox/omniscan/pkg/scanner/trivy"
)

func TestScannerCollectsFilesystemAndInstalledSoftwarePackagesWithoutDatabase(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"etc/os-release": "ID=windows\n",
		"Program Files/nodejs/node_modules/@openai/codex/package.json": `{"name":"@openai/codex","version":"0.4.0"}`,
		"Program Files/nodejs/package-lock.json": `{
			"version":"1.0.0",
			"lockfileVersion":1,
			"requires":true,
			"dependencies":{"left-pad":{"version":"1.3.0","resolved":"https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"}}
		}`,
		"Program Files/Python/requirements.txt":                              "requests==2.31.0\n",
		"Program Files/Python/Lib/site-packages/demo-2.4.dist-info/METADATA": "Metadata-Version: 2.1\nName: demo\nVersion: 2.4\n",
		"Program Files/Go/go.mod": `module example.com/windowsinventory

go 1.22

require github.com/pkg/errors v0.9.1
`,
		"Program Files/Rust/Cargo.lock": `version = 3

[[package]]
name = "fixture"
version = "0.1.0"
dependencies = ["serde 1.0.188"]

[[package]]
name = "serde"
version = "1.0.188"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
`,
		"Program Files/NuGet/packages.lock.json": `{
			"version":1,
			"dependencies":{
				".NETCoreApp,Version=v8.0":{
					"Newtonsoft.Json":{
						"type":"Direct","requested":"[13.0.1, )","resolved":"13.0.1",
						"contentHash":"6mgjfnRB4jKMlzHSl+VD+oUc1IebOZabkbyWj2RiTgWwYPPuaK1H97G1sHqGwPlS5npiF5Q0OrxN1wni2n5QWg=="
					}
				}
			}
		}`,
		"Program Files/Example/app.jar": "fixture",
	}
	for name, contents := range files {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("creating fixture directory: %v", err)
		}
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatalf("writing fixture file %q: %v", name, err)
		}
	}

	noDatabaseDir := filepath.Join(t.TempDir(), "empty-cache")
	s := NewScanner(WithCacheDirectory(noDatabaseDir))
	s.listDrives = func() ([]string, error) { return []string{root}, nil }
	s.discoverPackages = func(context.Context) ([]SoftwarePackage, error) {
		return []SoftwarePackage{{
			Name:            "Example Desktop",
			Version:         "1.2.3",
			Vendor:          "Example Corp",
			InstallLocation: filepath.Join(root, "Program Files", "Example"),
			Source:          "windows-registry-machine-64-bit",
			Identifier:      "{example-guid}",
		}, executablePackage(filepath.Join(root, "Program Files", "Example", "example.exe")),
			{
				Name:       "@openai/codex",
				Version:    "0.4.0",
				Source:     "npm-global",
				Identifier: "@openai/codex",
			},
			{
				Name:       "eslint",
				Version:    "8.0.0",
				Source:     "npm-global",
				Identifier: "eslint",
			},
			{
				Name:       "transformers",
				Version:    "4.50.0",
				Source:     "pip-global",
				Identifier: "transformers",
			},
		}, nil
	}

	finding, err := s.Scan(context.Background(), root, "vm://windows-inventory", "agent", "windows")
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	report, ok := finding.(*trivyScanner.Result)
	if !ok {
		t.Fatalf("Scan() returned %T, want *trivy.Result", finding)
	}
	if report.Metadata.Windows == nil || len(report.Metadata.Windows.InstalledSoftware) != 5 {
		t.Fatalf("Windows software metadata missing: %+v", report.Metadata.Windows)
	}
	var publisherFound bool
	for _, software := range report.Metadata.Windows.InstalledSoftware {
		if software.Name == "Example Desktop" && software.Publisher == "Example Corp" {
			publisherFound = true
		}
	}
	if !publisherFound {
		t.Fatalf("publisher metadata missing: %+v", report.Metadata.Windows.InstalledSoftware)
	}

	var packageManifestFound, registryPackageFound bool
	var executableMetadataFound bool
	resultTypes := make(map[string]bool)
	packageCounts := make(map[string]map[string]int)
	for _, result := range report.Results {
		if len(result.Vulnerabilities) > 0 {
			t.Fatalf("inventory result %q contains vulnerability data", result.Target)
		}
		resultTypes[string(result.Type)] = true
		if packageCounts[string(result.Type)] == nil {
			packageCounts[string(result.Type)] = make(map[string]int)
		}
		for _, pkg := range result.Packages {
			packageCounts[string(result.Type)][pkg.Name]++
			switch pkg.Name {
			case "@openai/codex":
				packageManifestFound = pkg.Version == "0.4.0"
			case "Example Desktop":
				registryPackageFound = pkg.Version == "1.2.3" &&
					pkg.Maintainer == "Example Corp" &&
					pkg.AnalyzedBy == ftypes.AnalyzerType("windows-registry-machine-64-bit")
				if pkg.Identifier.PURL == nil || pkg.Identifier.PURL.Type != "generic" {
					t.Fatalf("expected generic PURL on registry package: %+v", pkg.Identifier)
				}
			case "example":
				executableMetadataFound = len(pkg.InstalledFiles) == 1 &&
					pkg.InstalledFiles[0] == filepath.Join(root, "Program Files", "Example", "example.exe")
			}
		}
	}
	if !packageManifestFound || !registryPackageFound || !executableMetadataFound {
		t.Fatalf("missing inventory packages: manifest=%t registry=%t executable=%t",
			packageManifestFound, registryPackageFound, executableMetadataFound)
	}
	for _, resultType := range []string{"node-pkg", "npm", "python-pkg", "pip", "gomod", "cargo", "nuget"} {
		if !resultTypes[resultType] {
			t.Errorf("missing expected Trivy package result type %q: %+v", resultType, report.Results)
		}
	}
	if resultTypes["jar"] {
		t.Fatal("JAR analyzer ran in offline inventory mode")
	}
	if packageCounts["node-pkg"]["@openai/codex"] != 1 {
		t.Fatalf("npm collector duplicated Trivy's package.json result: %+v", packageCounts["node-pkg"])
	}
	if packageCounts["node-pkg"]["eslint"] != 1 || packageCounts["python-pkg"]["transformers"] != 1 {
		t.Fatalf("global npm/Python packages were not mapped to ecosystem result groups: %+v", packageCounts)
	}
	var registryResultFound, npmResultFound, pythonResultFound bool
	for _, result := range report.Results {
		switch {
		case result.Class == trivyTypes.ClassOSPkg && result.Type == "windows-software":
			for _, pkg := range result.Packages {
				registryResultFound = registryResultFound || pkg.Name == "Example Desktop"
			}
		case result.Class == trivyTypes.ClassLangPkg && result.Type == "node-pkg":
			for _, pkg := range result.Packages {
				if pkg.Name == "eslint" && pkg.Identifier.PURL != nil && pkg.Identifier.PURL.Type == "npm" {
					npmResultFound = true
				}
			}
		case result.Class == trivyTypes.ClassLangPkg && result.Type == "python-pkg":
			for _, pkg := range result.Packages {
				if pkg.Name == "transformers" && pkg.Identifier.PURL != nil && pkg.Identifier.PURL.Type == "pypi" {
					pythonResultFound = true
				}
			}
		}
	}
	if !registryResultFound || !npmResultFound || !pythonResultFound {
		t.Fatalf("native package result groups are incorrect: registry=%t npm=%t python=%t results=%+v",
			registryResultFound, npmResultFound, pythonResultFound, report.Results)
	}
	for _, dbDir := range []string{"db", "java-db"} {
		if _, err := os.Stat(filepath.Join(noDatabaseDir, dbDir)); !os.IsNotExist(err) {
			t.Fatalf("inventory unexpectedly initialized %s: %v", dbDir, err)
		}
	}
}

func TestPackageSignalsFromInventoryFeedExistingAgentDetector(t *testing.T) {
	root := t.TempDir()
	executable := filepath.Join(root, "CODEX.EXE")
	if err := os.WriteFile(executable, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	extensionDir := filepath.Join(root, ".vscode", "extensions", "openai.chatgpt-1.0")
	if err := os.MkdirAll(extensionDir, 0o755); err != nil {
		t.Fatal(err)
	}
	packages := ftypes.Packages{{
		Name:           "@openai/codex",
		Version:        "0.4.0",
		FilePath:       filepath.Join(root, "node_modules", "@openai", "codex", "package.json"),
		InstalledFiles: []string{executable},
	}}
	result := trivyTypes.Results{{Packages: packages}}
	signals := aiagent.PackageSignalsFromTrivyResults(result)
	catalog := &aiagent.Catalog{Agents: []aiagent.Agent{{
		ID: "codex",
		Installations: []aiagent.Installation{{Signals: aiagent.Signals{
			Packages:    []string{"@openai/codex"},
			Executables: []string{"codex"},
			Paths:       []string{"**/.vscode/extensions/openai.chatgpt-*"},
		}}},
	}}}
	detections := aiagent.Detect(catalog, []string{root}, signals, "windows")
	if len(detections) != 1 || len(detections[0].Detections) != 3 {
		t.Fatalf("package, executable, and extension path signals were not all detected: %+v", detections)
	}
	explicitDetections := aiagent.Detect(catalog, nil, signals, "windows")
	if len(explicitDetections) != 1 || len(explicitDetections[0].Detections) != 2 {
		t.Fatalf("package and explicit InstalledFiles executable signals were not detected without filesystem roots: %+v", explicitDetections)
	}
	foundExecutable := false
	for _, detection := range explicitDetections[0].Detections {
		if detection.Type == "executable" && detection.Value == executable {
			foundExecutable = true
		}
	}
	if !foundExecutable {
		t.Fatalf("InstalledFiles executable path was not passed as an explicit detector signal: %+v", explicitDetections[0].Detections)
	}
}

func TestScannerContinuesAfterDriveScanFailure(t *testing.T) {
	s := NewScanner()
	s.listDrives = func() ([]string, error) {
		return []string{`C:\`, `D:\`}, nil
	}
	var scanned []string
	s.scanRoot = func(_ context.Context, drive, _, _, _, _ string) (scanner.Findings, error) {
		scanned = append(scanned, drive)
		if drive == `C:\` {
			return nil, errors.New("drive unavailable")
		}
		return &trivyScanner.Result{
			ArtifactType: "rootfs",
			Results: trivyTypes.Results{{Target: "manifest.json", Packages: ftypes.Packages{{
				Name:    "remaining-drive-package",
				Version: "1.0",
			}}}},
		}, nil
	}
	s.discoverPackages = func(context.Context) ([]SoftwarePackage, error) {
		return nil, nil
	}

	finding, err := s.Scan(context.Background(), "", "vm://windows-inventory", "agent", "windows")
	if err != nil {
		t.Fatalf("Scan() error = %v, want failed drive to be skipped", err)
	}
	if len(scanned) != 2 || scanned[0] != `C:\` || scanned[1] != `D:\` {
		t.Fatalf("scanned drives = %v, want both C: and D:", scanned)
	}
	report := finding.(*trivyScanner.Result)
	if len(report.Results) != 1 || len(report.Results[0].Packages) != 1 ||
		report.Results[0].Packages[0].Name != "remaining-drive-package" {
		t.Fatalf("remaining drive package was not retained: %+v", report.Results)
	}
}
