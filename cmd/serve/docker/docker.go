// Package docker serves a remote suitable for use with docker volume api
package docker

import (
	"context"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/rclone/rclone/cmd"
	"github.com/rclone/rclone/cmd/mountlib"
	"github.com/rclone/rclone/fs/config/flags"
	"github.com/rclone/rclone/vfs"
	"github.com/rclone/rclone/vfs/vfsflags"
)

var (
	pluginName  = "rclone"
	pluginScope = "local"
	baseDir     = "/var/lib/docker-volumes/rclone"
	sockDir     = "/run/docker/plugins"
	defSpecDir  = "/etc/docker/plugins"
	stateFile   = "docker-plugin.state"
	socketAddr  = "" // TCP listening address or empty string for Unix socket
	socketGid   = syscall.Getgid()
	canPersist  = false // allows writing to config file
	forgetState = false
	noSpec      = false
	waitTimeout = 1 * time.Hour
)

func init() {
	cmdFlags := Command.Flags()
	// Add command specific flags
	flags.StringVarP(cmdFlags, &baseDir, "base-dir", "", baseDir, "Base directory for volumes")
	flags.StringVarP(cmdFlags, &socketAddr, "socket-addr", "", socketAddr, "Address <host:port> or absolute path (default: /run/docker/plugins/rclone.sock)")
	flags.IntVarP(cmdFlags, &socketGid, "socket-gid", "", socketGid, "GID for unix socket (default: current process GID)")
	flags.BoolVarP(cmdFlags, &forgetState, "forget-state", "", forgetState, "Skip restoring previous state")
	flags.BoolVarP(cmdFlags, &noSpec, "no-spec", "", noSpec, "Do not write spec file")
	flags.DurationVarP(cmdFlags, &waitTimeout, "mount-timeout", "", waitTimeout, "maximum time to wait for mount")
	// Add common mount/vfs flags
	mountlib.AddFlags(cmdFlags)
	vfsflags.AddFlags(cmdFlags)
}

// Command definition for cobra
var Command = &cobra.Command{
	Use:   "docker",
	Short: `Serve any remote on docker's volume plugin API.`,
	Long:  strings.ReplaceAll(longHelp, "|", "`") + vfs.Help,

	Run: func(command *cobra.Command, args []string) {
		cmd.CheckArgs(0, 0, command, args)
		cmd.Run(false, false, command, func() error {
			drv, err := NewDriver(context.Background(), baseDir, nil, nil, false, forgetState)
			if err != nil {
				return err
			}
			srv := NewServer(drv)
			if socketAddr == "" {
				// Listen on unix socket at /run/docker/plugins/<pluginName>.sock
				return srv.ServeUnix(pluginName, socketGid)
			}
			if filepath.IsAbs(socketAddr) {
				// Listen on unix socket at given path
				return srv.ServeUnix(socketAddr, socketGid)
			}
			return srv.ServeTCP(socketAddr, "", nil, noSpec)
		})
	},
}
