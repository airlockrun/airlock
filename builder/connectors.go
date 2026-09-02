package builder

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"
	"time"

	"github.com/airlockrun/agentsdk/connector/protocol"
	"github.com/airlockrun/airlock/container"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/jackc/pgx/v5/pgtype"
)

const (
	connectorManifestLimit   = protocol.MaxManifestBytes
	connectorManifestTimeout = 30 * time.Second
)

type connectorPackage struct {
	slug        string
	packagePath string
}

type connectorManifest = protocol.Manifest

type builtConnectorFile struct {
	platform    string
	filename    string
	path        string
	digest      string
	size        int64
	notices     []byte
	noticesHash string
}

type builtConnector struct {
	slug          string
	manifest      connectorManifest
	interfaceJSON []byte
	settingsJSON  []byte
	files         []builtConnectorFile
}

func discoverConnectorPackages(projectDir string) ([]connectorPackage, error) {
	root := filepath.Join(projectDir, "connectors")
	info, err := os.Lstat(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("inspect connectors directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, errors.New("connectors must be a real directory, not a file or symlink")
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("read connectors directory: %w", err)
	}
	packages := make([]connectorPackage, 0, len(entries))
	for _, entry := range entries {
		entryInfo, err := os.Lstat(filepath.Join(root, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("inspect connectors/%s: %w", entry.Name(), err)
		}
		if entryInfo.Mode()&os.ModeSymlink != 0 || !entryInfo.IsDir() {
			return nil, fmt.Errorf("connectors/%s must be a real directory; every immediate child is a connector", entry.Name())
		}
		if protocol.ValidateKind(entry.Name()) != nil {
			return nil, fmt.Errorf("connector slug %q must contain lowercase letters, digits, and internal hyphens", entry.Name())
		}
		packages = append(packages, connectorPackage{slug: entry.Name(), packagePath: "./connectors/" + entry.Name()})
	}
	sort.Slice(packages, func(i, j int) bool { return packages[i].slug < packages[j].slug })
	return packages, nil
}

func decodeConnectorManifest(raw []byte, slug string) (connectorManifest, []byte, []byte, error) {
	if len(raw) == 0 || len(raw) > connectorManifestLimit+1 {
		return connectorManifest{}, nil, nil, errors.New("connector manifest must be between 1 byte and 4 MiB")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var manifest connectorManifest
	if err := decoder.Decode(&manifest); err != nil {
		return connectorManifest{}, nil, nil, fmt.Errorf("decode connector manifest: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return connectorManifest{}, nil, nil, errors.New("connector manifest contains trailing JSON")
	}
	if err := validateConnectorManifest(manifest, slug); err != nil {
		return connectorManifest{}, nil, nil, err
	}
	interfaceJSON, err := json.Marshal(manifest.Interface)
	if err != nil {
		return connectorManifest{}, nil, nil, err
	}
	settingsJSON, err := json.Marshal(manifest.Settings)
	if err != nil {
		return connectorManifest{}, nil, nil, err
	}
	return manifest, interfaceJSON, settingsJSON, nil
}

func validateConnectorManifest(manifest connectorManifest, slug string) error {
	if err := protocol.ValidateManifest(manifest); err != nil {
		return err
	}
	if manifest.Interface.Kind != slug {
		return fmt.Errorf("connector %s manifest kind is %q; kind must match its directory slug", slug, manifest.Interface.Kind)
	}
	return nil
}

func (b *BuildService) buildConnectorArtifacts(ctx context.Context, agentID, sourceRef string, buildID pgtype.UUID, repoPath, goProxyDir string, logLine func(string)) error {
	packages, err := discoverConnectorPackages(repoPath)
	if err != nil {
		return err
	}
	if len(packages) == 0 {
		return nil
	}
	outputDir, err := b.makeCodegenTempDir("airlock-connectors-*")
	if err != nil {
		return fmt.Errorf("create connector artifact workspace: %w", err)
	}
	defer os.RemoveAll(outputDir)
	built := make([]builtConnector, 0, len(packages))
	for _, pkg := range packages {
		logLine(fmt.Sprintf("Building connector %s manifest binary...", pkg.slug))
		nativeName := "manifest-" + pkg.slug
		if err := b.containers.BuildConnectorBinary(ctx, container.ConnectorBuildOpts{
			SourceDir: repoPath, OutputDir: outputDir, Package: pkg.packagePath,
			Filename: nativeName, GoProxyDir: goProxyDir,
		}); err != nil {
			return fmt.Errorf("connector %s native build: %w", pkg.slug, err)
		}
		manifestCtx, cancelManifest := context.WithTimeout(ctx, connectorManifestTimeout)
		manifestRaw, err := b.containers.InspectConnectorManifest(manifestCtx, filepath.Join(outputDir, nativeName))
		cancelManifest()
		if err != nil {
			return fmt.Errorf("connector %s manifest: %w", pkg.slug, err)
		}
		manifest, interfaceJSON, settingsJSON, err := decodeConnectorManifest(manifestRaw, pkg.slug)
		if err != nil {
			return fmt.Errorf("connector %s manifest: %w", pkg.slug, err)
		}
		artifact := builtConnector{slug: pkg.slug, manifest: manifest, interfaceJSON: interfaceJSON, settingsJSON: settingsJSON}
		for _, platform := range manifest.Targets {
			filename := connectorArtifactFilename(pkg.slug, platform)
			logLine(fmt.Sprintf("Building connector %s for %s (CGO_ENABLED=0)...", pkg.slug, platform))
			if err := b.containers.BuildConnectorBinary(ctx, container.ConnectorBuildOpts{
				SourceDir: repoPath, OutputDir: outputDir, Package: pkg.packagePath,
				Filename: filename, Platform: platform, GoProxyDir: goProxyDir,
			}); err != nil {
				return fmt.Errorf("connector %s target %s: %w", pkg.slug, platform, err)
			}
			path := filepath.Join(outputDir, filename)
			digest, size, err := digestFile(path)
			if err != nil {
				return fmt.Errorf("connector %s target %s digest: %w", pkg.slug, platform, err)
			}
			notices, err := connectorNotices(path, repoPath, pkg.slug, platform, sourceRef)
			if err != nil {
				return fmt.Errorf("connector %s target %s notices: %w", pkg.slug, platform, err)
			}
			noticesSum := sha256.Sum256(notices)
			artifact.files = append(artifact.files, builtConnectorFile{
				platform: platform, filename: filename, path: path, digest: digest, size: size,
				notices: notices, noticesHash: hex.EncodeToString(noticesSum[:]),
			})
		}
		built = append(built, artifact)
	}
	return b.uploadConnectorArtifacts(ctx, mustParseUUID(agentID), buildID, sourceRef, built)
}

func connectorArtifactFilename(slug, platform string) string {
	target, ok := protocol.LookupTarget(platform)
	if !ok {
		panic("builder: validated connector target is not registered: " + platform)
	}
	return slug + "-" + platform + target.ExecutableSuffix
}

func digestFile(path string) (string, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	hash := sha256.New()
	size, err := io.Copy(hash, file)
	if err != nil {
		return "", 0, err
	}
	if size <= 0 {
		return "", 0, errors.New("compiled connector is empty")
	}
	return hex.EncodeToString(hash.Sum(nil)), size, nil
}

func connectorNotices(path, repoPath, slug, platform, sourceRef string) ([]byte, error) {
	info, err := buildinfo.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out strings.Builder
	fmt.Fprintf(&out, "# Third-Party Notices\n\nConnector: `%s`\nPlatform: `%s`\nSource revision: `%s`\n\n", slug, platform, sourceRef)
	out.WriteString("The executable records the following linked Go modules. Module license terms remain controlling.\n\n")
	modules := append([]*debug.Module(nil), info.Deps...)
	sort.Slice(modules, func(i, j int) bool { return modules[i].Path < modules[j].Path })
	for _, module := range modules {
		version, sum := module.Version, module.Sum
		if module.Replace != nil {
			version, sum = module.Replace.Version, module.Replace.Sum
		}
		if version == "" {
			version = "(local)"
		}
		fmt.Fprintf(&out, "- `%s` `%s`", module.Path, version)
		if sum != "" {
			fmt.Fprintf(&out, " `%s`", sum)
		}
		out.WriteByte('\n')
	}
	for _, name := range []string{"THIRD_PARTY_NOTICES.generated.md", "THIRD_PARTY_NOTICES.md"} {
		noticePath := filepath.Join(repoPath, name)
		fileInfo, err := os.Lstat(noticePath)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if !fileInfo.Mode().IsRegular() || fileInfo.Mode()&os.ModeSymlink != 0 || fileInfo.Size() > 2<<20 {
			return nil, fmt.Errorf("%s must be a regular file no larger than 2 MiB", name)
		}
		body, err := os.ReadFile(noticePath)
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(&out, "\n## %s\n\n", name)
		out.Write(body)
		if len(body) == 0 || body[len(body)-1] != '\n' {
			out.WriteByte('\n')
		}
	}
	return []byte(out.String()), nil
}

func (b *BuildService) uploadConnectorArtifacts(ctx context.Context, agentID, buildID pgtype.UUID, sourceRef string, artifacts []builtConnector) error {
	lock, err := b.db.AcquireAdvisoryLock(ctx, "connector-artifact-gc")
	if err != nil {
		return fmt.Errorf("lock connector artifact storage: %w", err)
	}
	defer lock.Unlock()
	q := dbq.New(b.db.Pool())
	for _, artifact := range artifacts {
		for _, file := range artifact.files {
			if err := b.uploadConnectorBlob(ctx, q, file.path, file.digest, file.size, "application/octet-stream"); err != nil {
				return err
			}
			if err := b.uploadConnectorNotice(ctx, q, file.notices, file.noticesHash); err != nil {
				return err
			}
		}
	}
	tx, err := b.db.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.Background())
	qtx := dbq.New(tx)
	for _, artifact := range artifacts {
		manifest := artifact.manifest
		artifactDigest, err := connectorArtifactSetDigest(sourceRef, manifest.InterfaceHash, artifact.files)
		if err != nil {
			return fmt.Errorf("digest connector %s artifact set: %w", artifact.slug, err)
		}
		set, err := qtx.CreateConnectorArtifactSet(ctx, dbq.CreateConnectorArtifactSetParams{
			AgentID: agentID, BuildID: buildID, ConnectorSlug: artifact.slug, SourceRef: sourceRef,
			Kind: manifest.Interface.Kind, ContractID: manifest.Interface.ContractID, Name: manifest.Interface.Name,
			Description: manifest.Interface.Description, ArtifactVersion: manifest.Interface.ArtifactVersion, ArtifactDigest: artifactDigest,
			ProtocolMajor: int32(manifest.ProtocolMajor), ProtocolMinor: int32(manifest.ProtocolMinor), Features: manifest.Features,
			InterfaceDescriptor: artifact.interfaceJSON,
			InterfaceHash:       manifest.InterfaceHash, SettingsSchema: artifact.settingsJSON,
		})
		if err != nil {
			return fmt.Errorf("persist connector %s artifact set: %w", artifact.slug, err)
		}
		for _, file := range artifact.files {
			if _, err := qtx.CreateConnectorArtifactFile(ctx, dbq.CreateConnectorArtifactFileParams{
				ArtifactSetID: set.ID, Platform: file.platform, Filename: file.filename,
				Digest: file.digest, SizeBytes: file.size, NoticesDigest: file.noticesHash,
				NoticesSizeBytes: int64(len(file.notices)),
			}); err != nil {
				return fmt.Errorf("persist connector %s target %s: %w", artifact.slug, file.platform, err)
			}
		}
	}
	return tx.Commit(ctx)
}

func connectorArtifactSetDigest(sourceRef, interfaceHash string, files []builtConnectorFile) (string, error) {
	type target struct {
		Platform      string `json:"platform"`
		Digest        string `json:"digest"`
		NoticesDigest string `json:"noticesDigest"`
	}
	targets := make([]target, len(files))
	for i, file := range files {
		targets[i] = target{Platform: file.platform, Digest: file.digest, NoticesDigest: file.noticesHash}
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].Platform < targets[j].Platform })
	raw, err := json.Marshal(struct {
		SourceRef     string   `json:"sourceRef"`
		InterfaceHash string   `json:"interfaceHash"`
		Targets       []target `json:"targets"`
	}{SourceRef: sourceRef, InterfaceHash: interfaceHash, Targets: targets})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func (b *BuildService) uploadConnectorBlob(ctx context.Context, q *dbq.Queries, path, digest string, size int64, mediaType string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	key := "connector-artifacts/sha256/" + digest
	if err := b.artifacts.PutObjectStream(ctx, key, file, size, mediaType); err != nil {
		return fmt.Errorf("upload connector artifact %s: %w", digest, err)
	}
	_, err = q.UpsertConnectorArtifactBlob(ctx, dbq.UpsertConnectorArtifactBlobParams{Digest: digest, ObjectKey: key, SizeBytes: size, MediaType: mediaType})
	return err
}

func (b *BuildService) uploadConnectorNotice(ctx context.Context, q *dbq.Queries, body []byte, digest string) error {
	key := "connector-artifacts/sha256/" + digest
	if err := b.artifacts.PutObjectStream(ctx, key, bytes.NewReader(body), int64(len(body)), "text/markdown; charset=utf-8"); err != nil {
		return fmt.Errorf("upload connector notices %s: %w", digest, err)
	}
	_, err := q.UpsertConnectorArtifactBlob(ctx, dbq.UpsertConnectorArtifactBlobParams{
		Digest: digest, ObjectKey: key, SizeBytes: int64(len(body)), MediaType: "text/markdown; charset=utf-8",
	})
	return err
}
