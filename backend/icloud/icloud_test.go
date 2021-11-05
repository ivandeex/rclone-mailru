// Test iCloud Drive filesystem interface
package icloud_test

import (
	"context"
	"os"
	"testing"

	"github.com/rclone/rclone/backend/icloud"
	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fstest/fstests"
)

// TestIntegration runs integration tests against the remote
func TestIntegration(t *testing.T) {
	if os.Getenv("RCLONE_VERBOSE_TEST") == "1" {
		fs.GetConfig(context.Background()).LogLevel = fs.LogLevelDebug
	}
	fstests.Run(t, &fstests.Opt{
		RemoteName: "icloud:",
		NilObject:  (*icloud.Object)(nil),
	})
}
