package update

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/vergecloud/cdn-cli/internal/version"
)

const (
	githubAPI = "https://api.github.com"
)

type Release struct {
	TagName string `json:"tag_name"`
	Assets  []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
}

type Info struct {
	Current     string
	Latest      string
	NeedsUpdate bool
	DownloadURL string
	ArchiveName string
}

func Check(ctx context.Context) (Info, error) {
	release, err := fetchLatestRelease(ctx)
	if err != nil {
		return Info{}, err
	}

	archive, url, err := platformAsset(release)
	if err != nil {
		return Info{}, err
	}

	current := normalizeVersion(version.Version)
	latest := normalizeVersion(release.TagName)

	return Info{
		Current:     current,
		Latest:      latest,
		NeedsUpdate: compareVersions(current, latest) < 0,
		DownloadURL: url,
		ArchiveName: archive,
	}, nil
}

func Apply(ctx context.Context) error {
	info, err := Check(ctx)
	if err != nil {
		return err
	}
	if !info.NeedsUpdate {
		return fmt.Errorf("already up to date (%s)", info.Current)
	}

	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve executable path: %w", err)
	}
	execPath, err = filepath.EvalSymlinks(execPath)
	if err != nil {
		return fmt.Errorf("resolve executable symlinks: %w", err)
	}

	tmpDir, err := os.MkdirTemp("", "verge-update-*")
	if err != nil {
		return fmt.Errorf("create temp directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	archivePath := filepath.Join(tmpDir, info.ArchiveName)
	if err := downloadFile(ctx, info.DownloadURL, archivePath); err != nil {
		return err
	}
	if err := verifyChecksum(ctx, info.ArchiveName, archivePath); err != nil {
		return err
	}

	binaryPath, err := extractBinary(archivePath, tmpDir)
	if err != nil {
		return err
	}

	backupPath := execPath + ".old"
	_ = os.Remove(backupPath)

	if err := os.Rename(execPath, backupPath); err != nil {
		return fmt.Errorf("backup current binary: %w", err)
	}

	if err := copyFile(binaryPath, execPath, 0o755); err != nil {
		_ = os.Rename(backupPath, execPath)
		return fmt.Errorf("install new binary: %w", err)
	}

	_ = os.Remove(backupPath)
	return nil
}

func fetchLatestRelease(ctx context.Context) (Release, error) {
	url := fmt.Sprintf("%s/repos/%s/releases/latest", githubAPI, version.GitHubRepo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Release{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", version.UserAgent)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return Release{}, fmt.Errorf("fetch latest release: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return Release{}, fmt.Errorf("fetch latest release: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var release Release
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return Release{}, fmt.Errorf("parse release metadata: %w", err)
	}
	if release.TagName == "" {
		return Release{}, fmt.Errorf("release metadata missing tag_name")
	}
	return release, nil
}

func platformAsset(release Release) (name, url string, err error) {
	osName := runtime.GOOS
	arch := runtime.GOARCH
	if osName == "windows" && arch == "arm64" {
		return "", "", fmt.Errorf("windows/arm64 is not published; download manually from https://github.com/%s/releases", version.GitHubRepo)
	}

	name = fmt.Sprintf("verge_%s_%s", osName, arch)
	switch osName {
	case "windows":
		name += ".zip"
	default:
		name += ".tar.gz"
	}

	for _, asset := range release.Assets {
		if asset.Name == name {
			return name, asset.BrowserDownloadURL, nil
		}
	}
	return "", "", fmt.Errorf("no release asset %q found; download manually from https://github.com/%s/releases", name, version.GitHubRepo)
}

func verifyChecksum(ctx context.Context, archiveName, archivePath string) error {
	url := fmt.Sprintf("https://github.com/%s/releases/latest/download/checksums.txt", version.GitHubRepo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", version.UserAgent)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("download checksums: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download checksums: HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read checksums: %w", err)
	}

	expected, ok := parseChecksum(string(body), archiveName)
	if !ok {
		return fmt.Errorf("checksum for %q not found in checksums.txt", archiveName)
	}

	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, f); err != nil {
		return fmt.Errorf("hash archive: %w", err)
	}
	actual := hex.EncodeToString(hash.Sum(nil))
	if !strings.EqualFold(actual, expected) {
		return fmt.Errorf("checksum mismatch for %s", archiveName)
	}
	return nil
}

func parseChecksum(content, archiveName string) (string, bool) {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) != 2 {
			continue
		}
		if parts[1] == archiveName {
			return parts[0], true
		}
	}
	return "", false
}

func extractBinary(archivePath, destDir string) (string, error) {
	if strings.HasSuffix(archivePath, ".zip") {
		return extractFromZip(archivePath, destDir)
	}
	return extractFromTarGz(archivePath, destDir)
}

func extractFromTarGz(archivePath, destDir string) (string, error) {
	f, err := os.Open(archivePath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return "", fmt.Errorf("open gzip archive: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("read tar archive: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		base := filepath.Base(hdr.Name)
		if base != "verge" && base != "verge.exe" {
			continue
		}
		outPath := filepath.Join(destDir, base)
		out, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
		if err != nil {
			return "", err
		}
		if _, err := io.Copy(out, tr); err != nil {
			out.Close()
			return "", err
		}
		out.Close()
		return outPath, nil
	}
	return "", fmt.Errorf("verge binary not found in archive")
}

func extractFromZip(archivePath, destDir string) (string, error) {
	r, err := zip.OpenReader(archivePath)
	if err != nil {
		return "", fmt.Errorf("open zip archive: %w", err)
	}
	defer r.Close()

	for _, file := range r.File {
		base := filepath.Base(file.Name)
		if base != "verge" && base != "verge.exe" {
			continue
		}
		rc, err := file.Open()
		if err != nil {
			return "", err
		}
		outPath := filepath.Join(destDir, base)
		out, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
		if err != nil {
			rc.Close()
			return "", err
		}
		_, copyErr := io.Copy(out, rc)
		closeErr := out.Close()
		rc.Close()
		if copyErr != nil {
			return "", copyErr
		}
		if closeErr != nil {
			return "", closeErr
		}
		return outPath, nil
	}
	return "", fmt.Errorf("verge binary not found in archive")
}

func downloadFile(ctx context.Context, url, dest string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", version.UserAgent)

	client := &http.Client{Timeout: 2 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("download %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download %s: HTTP %d", url, resp.StatusCode)
	}

	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, resp.Body); err != nil {
		return fmt.Errorf("write download: %w", err)
	}
	return nil
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Close()
}

func normalizeVersion(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	if v == "" || v == "dev" {
		return "0.0.0-dev"
	}
	return v
}

func compareVersions(current, latest string) int {
	curParts := strings.Split(current, ".")
	latParts := strings.Split(latest, ".")
	maxLen := len(curParts)
	if len(latParts) > maxLen {
		maxLen = len(latParts)
	}
	for i := 0; i < maxLen; i++ {
		cur := "0"
		lat := "0"
		if i < len(curParts) {
			cur = curParts[i]
		}
		if i < len(latParts) {
			lat = latParts[i]
		}
		cur = strings.TrimSuffix(cur, "-dev")
		lat = strings.TrimSuffix(lat, "-dev")
		if cur == lat {
			continue
		}
		if cur < lat {
			return -1
		}
		return 1
	}
	return 0
}
