// Test BaiduPCS filesystem interface
package baidupcs_test

import (
	"context"
	"os"
	"testing"

	"github.com/rclone/rclone/backend/baidupcs"
	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fstest/fstests"
)

// TestIntegration runs integration tests against the remote
func TestIntegration(t *testing.T) {
	if os.Getenv("BAIDUPCS_VERBOSE_TEST") == "1" {
		fs.GetConfig(context.Background()).LogLevel = fs.LogLevelDebug
	}
	fstests.Run(t, &fstests.Opt{
		RemoteName: "baidudev:",
		NilObject:  (*baidupcs.Object)(nil),
	})
}
