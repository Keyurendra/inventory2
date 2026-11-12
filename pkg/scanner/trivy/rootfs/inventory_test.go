package rootfs

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/aquasecurity/trivy/pkg/commands/artifact"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	fanalArtifact "github.com/aquasecurity/trivy/pkg/fanal/artifact"
	fanalLocal "github.com/aquasecurity/trivy/pkg/fanal/artifact/local"
	flanalTypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/fanal/walker"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/scan"
	"github.com/aquasecurity/trivy/pkg/types"
)

type countingInventoryWalker struct {
	delegate fanalLocal.Walker
	calls    int
}

func (w *countingInventoryWalker) Walk(root string, option walker.Option, fn walker.WalkFunc) error {
	w.calls++
	return w.delegate.Walk(root, option, fn)
}

func TestInventoryArtifactOptionRemovesOnlyLockfileExclusions(t *testing.T) {
	disabled := append(slices.Clone(analyzer.TypeLockfiles), analyzer.TypeJar, analyzer.TypeSecret)
	option := inventoryArtifactOption(fanalArtifact.Option{DisabledAnalyzers: disabled})

	if !slices.Contains(option.DisabledAnalyzers, analyzer.TypeJar) {
		t.Fatal("JAR analyzer exclusion was removed")
	}
	if !slices.Contains(option.DisabledAnalyzers, analyzer.TypeSecret) {
		t.Fatal("secret analyzer exclusion was removed")
	}
	for _, analyzerType := range analyzer.TypeLockfiles {
		if slices.Contains(option.DisabledAnalyzers, analyzerType) {
			t.Errorf("lockfile analyzer %q remains disabled", analyzerType)
		}
	}
}

func TestInventoryScanEnablesLockfileAnalyzersInOneTraversal(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"node_modules/installed-fixture/package.json": `{"name":"installed-fixture","version":"1.2.3"}`,
		"package-lock.json": `{
			"name":"inventory-root",
			"version":"1.0.0",
			"lockfileVersion":1,
			"requires":true,
			"dependencies":{
				"locked-fixture":{
					"version":"2.3.4",
					"resolved":"https://registry.npmjs.org/locked-fixture/-/locked-fixture-2.3.4.tgz"
				}
			}
		}`,
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

	cacheDir := filepath.Join(t.TempDir(), "cache")
	options := flag.Options{
		GlobalOptions: flag.GlobalOptions{
			CacheDir: cacheDir,
			Timeout:  time.Minute,
			Quiet:    true,
		},
		CacheOptions: flag.CacheOptions{
			CacheBackend: "fs",
		},
		ScanOptions: flag.ScanOptions{
			Scanners:          types.Scanners{types.SBOMScanner},
			DisableTelemetry:  true,
			OfflineScan:       true,
			SkipVersionCheck:  true,
			Target:            root,
			DetectionPriority: flanalTypes.PriorityPrecise,
		},
		VulnerabilityOptions: flag.VulnerabilityOptions{
			SkipVEXRepoUpdate: true,
		},
		PackageOptions: flag.PackageOptions{
			PkgTypes: []string{"os", "library"},
			PkgRelationships: []flanalTypes.Relationship{
				flanalTypes.RelationshipUnknown,
				flanalTypes.RelationshipRoot,
				flanalTypes.RelationshipWorkspace,
				flanalTypes.RelationshipDirect,
				flanalTypes.RelationshipIndirect,
			},
		},
		ReportOptions: flag.ReportOptions{
			Format:      types.FormatJSON,
			ListAllPkgs: true,
		},
	}

	filesystem := &countingInventoryWalker{delegate: walker.NewFS()}
	var disabledAnalyzers []analyzer.Type
	initializer := func(ctx context.Context, conf artifact.ScannerConfig) (scan.Service, func(), error) {
		disabledAnalyzers = slices.Clone(conf.ArtifactOption.DisabledAnalyzers)
		return initializeInventoryScanServiceWithWalker(conf, filesystem)
	}
	runner, err := artifact.NewRunner(
		context.Background(),
		options,
		artifact.TargetRootfs,
		artifact.WithInitializeService(initializer),
	)
	if err != nil {
		t.Fatalf("initializing Trivy runner: %v", err)
	}
	defer runner.Close(context.Background())

	report, err := runner.ScanRootfs(context.Background(), options)
	if err != nil {
		t.Fatalf("scanning inventory fixtures: %v", err)
	}
	if filesystem.calls != 1 {
		t.Fatalf("filesystem traversals = %d, want exactly one", filesystem.calls)
	}
	if !slices.Contains(disabledAnalyzers, analyzer.TypeJar) {
		t.Fatal("JAR analyzer was not disabled")
	}

	var individualPackageFound, lockfilePackageFound bool
	for _, result := range report.Results {
		if result.Type == "jar" {
			t.Fatal("JAR result was included in inventory mode")
		}
		if result.Class != types.ClassLangPkg {
			continue
		}
		for _, pkg := range result.Packages {
			switch {
			case result.Type == "node-pkg" && pkg.Name == "installed-fixture" && pkg.Version == "1.2.3":
				individualPackageFound = true
			case result.Type == "npm" && pkg.Name == "locked-fixture" && pkg.Version == "2.3.4":
				lockfilePackageFound = true
			}
		}
	}
	if !individualPackageFound || !lockfilePackageFound {
		t.Fatalf("missing packages from combined analyzer scan: individual=%t lockfile=%t results=%+v",
			individualPackageFound, lockfilePackageFound, report.Results)
	}

	for _, databaseDir := range []string{"db", "java-db"} {
		if _, err := os.Stat(filepath.Join(cacheDir, databaseDir)); !os.IsNotExist(err) {
			t.Fatalf("inventory initialized %s: %v", databaseDir, err)
		}
	}
}
