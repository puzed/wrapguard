package main

import (
	"bufio"
	"debug/macho"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"
)

const (
	envWrapGuardIPCPath   = "WRAPGUARD_IPC_PATH"
	envWrapGuardSOCKSPort = "WRAPGUARD_SOCKS_PORT"
	envWrapGuardDebug     = "WRAPGUARD_DEBUG"
	envWrapGuardDebugIPC  = "WRAPGUARD_DEBUG_IPC"
	envWrapGuardBlockUDP  = "WRAPGUARD_BLOCK_UDP_443"
	envWrapGuardNoInherit = "WRAPGUARD_MACOS_NO_INHERIT"
	envWrapGuardExpectRDY = "WRAPGUARD_EXPECT_READY"
)

type injectionConfig struct {
	LibraryName           string
	LibraryEnvVar         string
	RequiresFlatNamespace bool
}

func currentInjectionConfig() (injectionConfig, error) {
	return injectionConfigForGOOS(runtime.GOOS)
}

func currentPlatformName() string {
	return runtime.GOOS
}

func injectionConfigForGOOS(goos string) (injectionConfig, error) {
	switch goos {
	case "linux":
		return injectionConfig{
			LibraryName:   "libwrapguard.so",
			LibraryEnvVar: "LD_PRELOAD",
		}, nil
	case "darwin":
		return injectionConfig{
			LibraryName:   "libwrapguard.dylib",
			LibraryEnvVar: "DYLD_INSERT_LIBRARIES",
		}, nil
	default:
		return injectionConfig{}, fmt.Errorf("unsupported platform: %s", goos)
	}
}

func resolveInjectedLibraryPath(execPath string) (string, injectionConfig, error) {
	cfg, err := currentInjectionConfig()
	if err != nil {
		return "", injectionConfig{}, err
	}

	candidateDirs := []string{filepath.Dir(execPath)}
	if invokedPath, err := exec.LookPath(os.Args[0]); err == nil {
		candidateDirs = append(candidateDirs, filepath.Dir(invokedPath))
	}

	var statErrs []string
	seen := make(map[string]struct{}, len(candidateDirs))
	for _, dir := range candidateDirs {
		if dir == "" {
			continue
		}
		dir = filepath.Clean(dir)
		if _, ok := seen[dir]; ok {
			continue
		}
		seen[dir] = struct{}{}

		libPath := filepath.Join(dir, cfg.LibraryName)
		if _, err := os.Stat(libPath); err == nil {
			return libPath, cfg, nil
		} else if os.IsNotExist(err) {
			statErrs = append(statErrs, libPath)
			continue
		} else {
			return "", injectionConfig{}, fmt.Errorf("failed to stat injection library %s: %w", libPath, err)
		}
	}

	return "", injectionConfig{}, fmt.Errorf("required injection library not found; searched: %s", strings.Join(statErrs, ", "))
}

func buildChildEnv(baseEnv []string, cfg injectionConfig, libraryPath, ipcPath string, socksPort int, debug bool, macOSNoInherit bool) []string {
	envMap := make(map[string]string, len(baseEnv)+6)
	envOrder := make([]string, 0, len(baseEnv)+6)

	for _, entry := range baseEnv {
		parts := strings.SplitN(entry, "=", 2)
		key := parts[0]
		value := ""
		if len(parts) == 2 {
			value = parts[1]
		}
		if _, exists := envMap[key]; !exists {
			envOrder = append(envOrder, key)
		}
		envMap[key] = value
	}

	setEnv := func(key, value string) {
		if _, exists := envMap[key]; !exists {
			envOrder = append(envOrder, key)
		}
		envMap[key] = value
	}
	unsetEnv := func(key string) {
		delete(envMap, key)
	}

	setEnv(cfg.LibraryEnvVar, mergeInjectionLibraryValue(cfg, envMap[cfg.LibraryEnvVar], libraryPath))
	if cfg.RequiresFlatNamespace {
		setEnv("DYLD_FORCE_FLAT_NAMESPACE", "1")
	} else if cfg.LibraryEnvVar == "DYLD_INSERT_LIBRARIES" {
		unsetEnv("DYLD_FORCE_FLAT_NAMESPACE")
	}
	setEnv(envWrapGuardExpectRDY, "1")
	setEnv(envWrapGuardIPCPath, ipcPath)
	setEnv(envWrapGuardSOCKSPort, fmt.Sprintf("%d", socksPort))
	if cfg.LibraryEnvVar == "DYLD_INSERT_LIBRARIES" {
		setEnv(envWrapGuardBlockUDP, "1")
		if macOSNoInherit {
			setEnv(envWrapGuardNoInherit, "1")
		}
	}
	if debug {
		setEnv(envWrapGuardDebug, "1")
		if cfg.LibraryEnvVar == "DYLD_INSERT_LIBRARIES" {
			setEnv(envWrapGuardDebugIPC, "1")
		}
	}

	result := make([]string, 0, len(envOrder))
	for _, key := range envOrder {
		value, ok := envMap[key]
		if !ok {
			continue
		}
		result = append(result, fmt.Sprintf("%s=%s", key, value))
	}

	return result
}

func initialHandshakeTimeout(goos, requestedTarget string) time.Duration {
	if goos != "darwin" {
		return 3 * time.Second
	}

	target := strings.TrimSpace(requestedTarget)
	if strings.Contains(target, ".app/") || strings.HasSuffix(target, ".app") {
		return 15 * time.Second
	}

	return 3 * time.Second
}

func mergeInjectionLibraryValue(cfg injectionConfig, existingValue, libraryPath string) string {
	if strings.TrimSpace(existingValue) == "" {
		return libraryPath
	}

	separator := ":"
	if cfg.LibraryEnvVar == "LD_PRELOAD" {
		separator = " "
	}

	for _, entry := range strings.FieldsFunc(existingValue, func(r rune) bool {
		return r == ':' || r == ' ' || r == '\t'
	}) {
		if entry == libraryPath {
			return existingValue
		}
	}

	return libraryPath + separator + existingValue
}

type launchTargetDetails struct {
	RequestedPath       string
	ResolvedPath        string
	InjectionTargetPath string
	UsedInterpreter     bool
	InterpreterPath     string
}

type launchTargetSecurityInfo struct {
	SigningStatus    string
	HardenedRuntime  string
	InspectionNotice string
}

func validateLaunchTargetWithLibrary(command, libraryPath string) (*launchTargetDetails, error) {
	if runtime.GOOS != "darwin" {
		return &launchTargetDetails{RequestedPath: command}, nil
	}

	details := &launchTargetDetails{
		RequestedPath: command,
	}

	resolvedPath := command
	var err error
	if strings.HasSuffix(command, ".app") {
		resolvedPath, err = resolveAppBundleExecutablePath(command)
		if err != nil {
			return nil, err
		}
		details.ResolvedPath = resolvedPath
	} else {
		resolvedPath, err = exec.LookPath(command)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve launch target %q: %w", command, err)
		}
	}

	if !filepath.IsAbs(resolvedPath) {
		resolvedPath, err = filepath.Abs(resolvedPath)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve launch target path: %w", err)
		}
	}

	details.InjectionTargetPath = resolvedPath

	if interpreterPath, ok, err := resolveScriptInterpreter(resolvedPath); err != nil {
		return nil, err
	} else if ok {
		details.UsedInterpreter = true
		details.InterpreterPath = interpreterPath
		details.InjectionTargetPath = interpreterPath
	}

	protectedPrefixes := []string{
		"/System/",
		"/bin/",
		"/sbin/",
		"/usr/bin/",
		"/usr/libexec/",
	}
	for _, prefix := range protectedPrefixes {
		if strings.HasPrefix(details.InjectionTargetPath, prefix) {
			if details.UsedInterpreter {
				return nil, fmt.Errorf("launch target %s uses SIP-protected interpreter %s and cannot be wrapped via DYLD injection", resolvedPath, details.InjectionTargetPath)
			}
			return nil, fmt.Errorf("launch target %s is protected by macOS SIP and cannot be wrapped via DYLD injection", details.InjectionTargetPath)
		}
	}

	if libraryPath != "" {
		targetArchs, err := machOArchitectures(details.InjectionTargetPath)
		if err != nil {
			return nil, fmt.Errorf("failed to inspect launch target architecture for %s: %w", details.InjectionTargetPath, err)
		}

		libraryArchs, err := machOArchitectures(libraryPath)
		if err != nil {
			return nil, fmt.Errorf("failed to inspect injection library architecture for %s: %w", libraryPath, err)
		}

		if !archSetsOverlap(targetArchs, libraryArchs) {
			return nil, fmt.Errorf(
				"launch target architecture %s is incompatible with injection library architecture %s",
				strings.Join(targetArchs, ", "),
				strings.Join(libraryArchs, ", "),
			)
		}
	}

	return details, nil
}

func validateLaunchTarget(command string) error {
	_, err := validateLaunchTargetWithLibrary(command, "")
	return err
}

func inspectLaunchTargetSecurityInfo(targetPath, codesignPath string) (launchTargetSecurityInfo, error) {
	if codesignPath == "" {
		var err error
		codesignPath, err = exec.LookPath("codesign")
		if err != nil {
			return launchTargetSecurityInfo{
				SigningStatus:   "unknown",
				HardenedRuntime: "unknown",
			}, fmt.Errorf("codesign tool not found: %w", err)
		}
	}

	cmd := exec.Command(codesignPath, "-dv", "--verbose=4", targetPath)
	output, err := cmd.CombinedOutput()
	info := parseLaunchTargetSecurityInfo(string(output))
	if info.SigningStatus == "" {
		info.SigningStatus = "unknown"
	}
	if info.HardenedRuntime == "" {
		info.HardenedRuntime = "unknown"
	}

	lowerOutput := strings.ToLower(string(output))
	if err == nil {
		return info, nil
	}

	if strings.Contains(lowerOutput, "code object is not signed at all") {
		if info.SigningStatus == "unknown" {
			info.SigningStatus = "unsigned"
		}
		if info.HardenedRuntime == "unknown" {
			info.HardenedRuntime = "disabled"
		}
		return info, nil
	}

	if info.SigningStatus != "unknown" || info.HardenedRuntime != "unknown" {
		return info, nil
	}

	return info, fmt.Errorf("failed to inspect code signature metadata: %w", err)
}

func parseLaunchTargetSecurityInfo(output string) launchTargetSecurityInfo {
	lowerOutput := strings.ToLower(output)
	info := launchTargetSecurityInfo{
		SigningStatus:   "unknown",
		HardenedRuntime: "unknown",
	}

	switch {
	case strings.Contains(lowerOutput, "code object is not signed at all"):
		info.SigningStatus = "unsigned"
		info.HardenedRuntime = "disabled"
	case strings.Contains(lowerOutput, "signature=adhoc"):
		info.SigningStatus = "ad-hoc"
	case strings.Contains(lowerOutput, "authority="):
		info.SigningStatus = "signed"
	}

	if strings.Contains(lowerOutput, "flags=") {
		if strings.Contains(lowerOutput, "runtime") {
			info.HardenedRuntime = "enabled"
			if info.SigningStatus == "signed" {
				info.InspectionNotice = "DYLD injection may still be rejected at runtime by the target's hardened runtime policy"
			}
		} else if info.HardenedRuntime == "unknown" {
			info.HardenedRuntime = "disabled"
		}
	}

	if info.SigningStatus == "ad-hoc" && info.HardenedRuntime == "unknown" {
		info.HardenedRuntime = "disabled"
	}

	return info
}

func reportLaunchTargetSecurityInfo(output io.Writer, targetPath, codesignPath string) error {
	info, err := inspectLaunchTargetSecurityInfo(targetPath, codesignPath)
	fmt.Fprintf(output, "doctor: target-signing=%s\n", info.SigningStatus)
	fmt.Fprintf(output, "doctor: target-hardened-runtime=%s\n", info.HardenedRuntime)
	if info.InspectionNotice != "" {
		fmt.Fprintf(output, "doctor: advisory: %s\n", info.InspectionNotice)
	}
	return err
}

func resolveAppBundleExecutablePath(bundlePath string) (string, error) {
	absBundlePath, err := filepath.Abs(bundlePath)
	if err != nil {
		return "", fmt.Errorf("failed to resolve app bundle path %s: %w", bundlePath, err)
	}

	info, err := os.Stat(absBundlePath)
	if err != nil {
		return "", fmt.Errorf("failed to inspect app bundle %s: %w", absBundlePath, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("%s is not a macOS app bundle directory", absBundlePath)
	}

	macOSDir := filepath.Join(absBundlePath, "Contents", "MacOS")
	entries, err := os.ReadDir(macOSDir)
	if err != nil {
		return "", fmt.Errorf("failed to inspect app bundle executable directory %s: %w", macOSDir, err)
	}

	baseName := strings.TrimSuffix(filepath.Base(absBundlePath), ".app")
	var candidatePath string
	candidateNames := make([]string, 0, len(entries))

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		entryInfo, err := entry.Info()
		if err != nil {
			return "", fmt.Errorf("failed to inspect app bundle executable %s: %w", filepath.Join(macOSDir, entry.Name()), err)
		}
		if entryInfo.Mode()&0o111 == 0 {
			continue
		}

		candidateNames = append(candidateNames, entry.Name())
		fullPath := filepath.Join(macOSDir, entry.Name())
		if entry.Name() == baseName {
			return fullPath, nil
		}
		if candidatePath == "" {
			candidatePath = fullPath
		}
	}

	if len(candidateNames) == 1 {
		return candidatePath, nil
	}
	if len(candidateNames) > 1 {
		slices.Sort(candidateNames)
		return "", fmt.Errorf(
			"app bundle %s has multiple executable candidates in Contents/MacOS: %s",
			absBundlePath,
			strings.Join(candidateNames, ", "),
		)
	}

	return "", fmt.Errorf("app bundle %s does not contain an executable in Contents/MacOS", absBundlePath)
}

func resolveScriptInterpreter(path string) (string, bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", false, fmt.Errorf("failed to inspect launch target %s: %w", path, err)
	}
	defer file.Close()

	reader := bufio.NewReader(file)
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", false, fmt.Errorf("failed to read launch target %s: %w", path, err)
	}
	if !strings.HasPrefix(line, "#!") {
		return "", false, nil
	}

	fields := strings.Fields(strings.TrimSpace(strings.TrimPrefix(line, "#!")))
	if len(fields) == 0 {
		return "", false, nil
	}

	interpreter := fields[0]
	if !filepath.IsAbs(interpreter) {
		resolved, err := exec.LookPath(interpreter)
		if err != nil {
			return "", false, fmt.Errorf("failed to resolve script interpreter %q for %s: %w", interpreter, path, err)
		}
		interpreter = resolved
	}

	if filepath.Base(interpreter) == "env" {
		for _, arg := range fields[1:] {
			if strings.HasPrefix(arg, "-") {
				continue
			}
			resolved, err := exec.LookPath(arg)
			if err == nil {
				interpreter = resolved
			}
			break
		}
	}

	interpreter, err = filepath.Abs(interpreter)
	if err != nil {
		return "", false, fmt.Errorf("failed to resolve interpreter path for %s: %w", path, err)
	}

	return interpreter, true, nil
}

func machOArchitectures(path string) ([]string, error) {
	if fat, err := macho.OpenFat(path); err == nil {
		defer fat.Close()

		archs := make([]string, 0, len(fat.Arches))
		for _, arch := range fat.Arches {
			archName := machoCPUArchName(arch.Cpu)
			if archName == "" {
				archName = fmt.Sprintf("cpu-%d", arch.Cpu)
			}
			archs = append(archs, archName)
		}
		return compactArchitectures(archs), nil
	}

	file, err := macho.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	archName := machoCPUArchName(file.Cpu)
	if archName == "" {
		archName = fmt.Sprintf("cpu-%d", file.Cpu)
	}
	return []string{archName}, nil
}

func machoCPUArchName(cpu macho.Cpu) string {
	switch cpu {
	case macho.CpuAmd64:
		return "amd64"
	case macho.CpuArm64:
		return "arm64"
	default:
		return ""
	}
}

func compactArchitectures(archs []string) []string {
	if len(archs) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(archs))
	result := make([]string, 0, len(archs))
	for _, arch := range archs {
		if arch == "" {
			continue
		}
		if _, ok := seen[arch]; ok {
			continue
		}
		seen[arch] = struct{}{}
		result = append(result, arch)
	}
	slices.Sort(result)
	return result
}

func archSetsOverlap(left, right []string) bool {
	for _, lhs := range left {
		for _, rhs := range right {
			if lhs == rhs {
				return true
			}
		}
	}
	return false
}
