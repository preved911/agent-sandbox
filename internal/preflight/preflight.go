// Package preflight performs platform-specific validation before starting
// the sandbox stack. On macOS, it verifies that the working directory is
// covered by Docker Desktop's or Colima's shared-paths configuration.
// On Linux, all checks are no-ops.
package preflight

// SharedPathsCheck validates that the given directory is accessible inside
// the Docker VM. On macOS this reads Docker Desktop settings or Colima
// mounts. On Linux this is a no-op (bind mounts always work).
func SharedPathsCheck(dir string) error {
	return sharedPathsCheckPlatform(dir)
}
