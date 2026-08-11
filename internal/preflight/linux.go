//go:build !darwin

package preflight

// sharedPathsCheckPlatform is a no-op on Linux — bind mounts always work.
func sharedPathsCheckPlatform(_ string) error {
	return nil
}
