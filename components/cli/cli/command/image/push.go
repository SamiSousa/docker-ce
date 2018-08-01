package image

import (
	"context"

	"github.com/docker/cli/cli"
	"github.com/docker/cli/cli/command"
	"github.com/docker/cli/cli/command/manifest"
	"github.com/docker/distribution/reference"
	"github.com/docker/docker/pkg/jsonmessage"
	"github.com/docker/docker/registry"
	"github.com/spf13/cobra"
)

type pushOptions struct {
	remote    string
	untrusted bool
	source	  string
}

// NewPushCommand creates a new `docker push` command
func NewPushCommand(dockerCli command.Cli) *cobra.Command {
	var opts pushOptions

	cmd := &cobra.Command{
		Use:   "push [OPTIONS] NAME[:TAG]",
		Short: "Push an image or a repository to a registry",
		Args:  cli.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.remote = args[0]
			return RunPush(dockerCli, opts)
		},
	}

	flags := cmd.Flags()

	flags.StringVar(&opts.source, "source", "", "Also push and add a source image reference to the main image")

	command.AddTrustSigningFlags(flags, &opts.untrusted, dockerCli.ContentTrustEnabled())

	return cmd
}

// RunPush performs a push against the engine based on the specified options
func RunPush(dockerCli command.Cli, opts pushOptions) error {
	if opts.source != "" {
		// Push the image and the source
		return sourceRefPush(dockerCli, opts)
	}

	ref, err := reference.ParseNormalizedNamed(opts.remote)
	if err != nil {
		return err
	}

	// Resolve the Repository name from fqn to RepositoryInfo
	repoInfo, err := registry.ParseRepositoryInfo(ref)
	if err != nil {
		return err
	}

	ctx := context.Background()

	// Resolve the Auth config relevant for this server
	authConfig := command.ResolveAuthConfig(ctx, dockerCli, repoInfo.Index)
	requestPrivilege := command.RegistryAuthenticationPrivilegedFunc(dockerCli, repoInfo.Index, "push")

	if !opts.untrusted {
		return TrustedPush(ctx, dockerCli, repoInfo, ref, authConfig, requestPrivilege)
	}

	responseBody, err := imagePushPrivileged(ctx, dockerCli, authConfig, ref, requestPrivilege)
	if err != nil {
		return err
	}

	defer responseBody.Close()
	return jsonmessage.DisplayJSONMessagesToStream(responseBody, dockerCli.Out(), nil)
}

func sourceRefPush(dockerCli command.Cli, opts pushOptions) error {
	// Check each reference for validity before pushing
	_, err := reference.ParseNormalizedNamed(opts.remote)
	if err != nil {
		return err
	}

	_, err = reference.ParseNormalizedNamed(opts.source)
	if err != nil {
		return err
	}

	// Push each image
	pushOpts := pushOptions{
		remote: opts.remote,
		untrusted: opts.untrusted,
		source: "",
	}

	err = RunPush(dockerCli, pushOpts)
	if err != nil {
		return err
	}

	pushOpts.remote = opts.source
	err = RunPush(dockerCli, pushOpts)
	if err != nil {
		return err
	}

	// Create manifest list to link together image and source
	err = manifest.CreateSourceManifestList(dockerCli, opts.remote, opts.source)
	if err != nil {
		return err
	}

	// Push manifest list
	return manifest.PushManifestList(dockerCli, opts.remote)
}