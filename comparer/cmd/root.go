package cmd

import (
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/jdolitsky/apko-compare/comparer/internal"
)

type subCommand func() (*cobra.Command, error)

var subCommands = []subCommand{}

func rootCmd() (*cobra.Command, error) {
	var (
		cmd                          *cobra.Command
		debug                        bool
		platforms                    []string
		ignoreContent                bool
		ignoreSize                   bool
		ignoreTimestamps             bool
		ignorePermissions            bool
		ignoreOwnership              bool
		ignoreExtraFiles             string
		ignoreMissingImage           bool
		username, password, proxyUrl string
		anonymous                    bool
		saveFilePattern              string
	)
	cmd = &cobra.Command{
		Use:   "compare-oci-filesystems",
		Short: "file-by-file comparison of the filesystems of two OCI images",
		Long: `Perform a file-by-file comparison of the filesystems of two OCI images
		If images are not the same architecture, will report an error. If the 
		images are multi-arch indexes, will compare each architecture, and report those
		that do not exist for both.

		Use CLI flags to restrict which architectures to compare, as well as
		limit files or parameters, such as date, size, etc.

			compare-oci-filesystems imageA imageB
		
		Sends output to stdout, unless a --save-file-pattern is specified.
		Logs to stderr.
		`,
		PersistentPreRun: func(c *cobra.Command, args []string) {
			if debug {
				log.SetLevel(log.DebugLevel)
			}
		},
		Args: cobra.ExactArgs(2),
		RunE: func(c *cobra.Command, args []string) error {
			// validate the save file pattern
			if saveFilePattern != "" {
				if !strings.Contains(saveFilePattern, "IMAGE") || !strings.Contains(saveFilePattern, "PLATFORM") {
					return fmt.Errorf("save file pattern '%s' must contain both IMAGE and PLATFORM", saveFilePattern)
				}
			}
			ignoreExtra := internal.ImageNeither
			switch ignoreExtraFiles {
			case "left":
				ignoreExtra = internal.ImageLeft
			case "right":
				ignoreExtra = internal.ImageRight
			case "both":
				ignoreExtra = internal.ImageBoth
			default:
				ignoreExtra = internal.ImageNeither
			}
			cfg := internal.Params{
				Platforms:          platforms,
				IgnoreContent:      ignoreContent,
				IgnoreSize:         ignoreSize,
				IgnoreTimestamps:   ignoreTimestamps,
				IgnorePermissions:  ignorePermissions,
				IgnoreOwnership:    ignoreOwnership,
				IgnoreExtraFiles:   ignoreExtra,
				IgnoreMissingImage: ignoreMissingImage,
				Proxy:              proxyUrl,
				Username:           username,
				Password:           password,
				Anonymous:          anonymous,
				SaveFilePattern:    saveFilePattern,
			}
			return internal.Run(args[0], args[1], cfg)
		},
	}

	// server hostname via CLI or env var
	flags := cmd.Flags()
	flags.BoolVar(&debug, "debug", false, "enable debug logging")
	flags.StringSliceVar(&platforms, "platform", []string{}, "limit to specific platforms (e.g. linux/amd64, linux/arm64, etc.); if empty, all archs found in both images")

	flags.BoolVar(&ignoreTimestamps, "ignore-timestamps", false, "ignore timestamps when comparing files")
	flags.BoolVar(&ignoreSize, "ignore-size", false, "ignore size when comparing files")
	flags.BoolVar(&ignoreContent, "ignore-content", false, "ignore content when comparing files")
	flags.BoolVar(&ignorePermissions, "ignore-permissions", false, "ignore permissions when comparing files")
	flags.BoolVar(&ignoreOwnership, "ignore-ownership", false, "ignore ownership when comparing files")
	flags.StringVar(&ignoreExtraFiles, "ignore-extra-files", "", "ignore files that exist in one of the images but not the other. Must be blank or one of: left, right, both")
	flags.BoolVar(&ignoreMissingImage, "ignore-missing-image", false, "if the left or right image is missing, ignore the error and just exit")
	flags.StringVar(&username, "username", "", "username to authenticate against registry")
	flags.StringVar(&password, "password", "", "password to authenticate against registry")
	flags.BoolVar(&anonymous, "anonymous", false, "use anonymous auth, defaults to your local credentials")
	flags.StringVar(&proxyUrl, "proxy", "", "proxy URL to use")
	flags.StringVar(&saveFilePattern, "save-file-pattern", "", "pattern to save output to files, replaces PLATFORM with the platform and IMAGE with the image name, unsafe characters replaced with -, e.g. 'out-IMAGE-PLATFORM-diff'")
	for _, subCmd := range subCommands {
		if sc, err := subCmd(); err != nil {
			return nil, err
		} else {
			cmd.AddCommand(sc)
		}
	}

	return cmd, nil
}

// Execute primary function for cobra
func Execute() {
	rootCmd, err := rootCmd()
	if err != nil {
		log.Fatal(err)
	}
	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
