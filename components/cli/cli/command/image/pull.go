package image

import (
	"context"
	"fmt"
	"strings"
	"runtime"

	"github.com/docker/cli/cli"
	"github.com/docker/cli/cli/command"
	"github.com/docker/cli/cli/trust"
	"github.com/docker/cli/cli/manifest/types"
	"github.com/containerd/containerd/platforms"
	"github.com/docker/distribution"
	"github.com/docker/distribution/manifest/manifestlist"
	"github.com/docker/distribution/reference"
	"github.com/docker/docker/registry"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

// PullOptions defines what and how to pull
type PullOptions struct {
	remote    string
	all       bool
	platform  string
	untrusted bool
	source bool
}

// NewPullCommand creates a new `docker pull` command
func NewPullCommand(dockerCli command.Cli) *cobra.Command {
	var opts PullOptions

	cmd := &cobra.Command{
		Use:   "pull [OPTIONS] NAME[:TAG|@DIGEST]",
		Short: "Pull an image or a repository from a registry",
		Args:  cli.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.remote = args[0]
			return RunPull(dockerCli, opts)
		},
	}

	flags := cmd.Flags()

	flags.BoolVarP(&opts.all, "all-tags", "a", false, "Download all tagged images in the repository")
	flags.BoolVar(&opts.source, "source", false, "Download source for specified image")

	command.AddPlatformFlag(flags, &opts.platform)
	command.AddTrustVerificationFlags(flags, &opts.untrusted, dockerCli.ContentTrustEnabled())

	return cmd
}

// RunPull performs a pull against the engine based on the specified options
func RunPull(cli command.Cli, opts PullOptions) error {
	distributionRef, err := reference.ParseNormalizedNamed(opts.remote)
	switch {
	case err != nil:
		return err
	case opts.all && !reference.IsNameOnly(distributionRef):
		return errors.New("tag can't be used with --all-tags/-a")
	case opts.all && opts.source:
		return errors.New("can't use --source with --all-tags/-a")
	case !opts.all && reference.IsNameOnly(distributionRef):
		distributionRef = reference.TagNameOnly(distributionRef)
		if tagged, ok := distributionRef.(reference.Tagged); ok {
			fmt.Fprintf(cli.Out(), "Using default tag: %s\n", tagged.Tag())
		}
	}

	// Check if source flag passed
	if opts.source {
		return sourcePull(cli, distributionRef, opts)
	}

	ctx := context.Background()
	imgRefAndAuth, err := trust.GetImageReferencesAndAuth(ctx, nil, AuthResolver(cli), distributionRef.String())
	if err != nil {
		return err
	}

	// Check if reference has a digest
	_, isCanonical := distributionRef.(reference.Canonical)
	if !opts.untrusted && !isCanonical {
		err = trustedPull(ctx, cli, imgRefAndAuth, opts.platform)
	} else {
		err = imagePullPrivileged(ctx, cli, imgRefAndAuth, opts.all, opts.platform)
	}
	if err != nil {
		if strings.Contains(err.Error(), "when fetching 'plugin'") {
			return errors.New(err.Error() + " - Use `docker plugin install`")
		}
		return err
	}
	return nil
}

// sourcePull attempts to pull the image source code based on the manifest list
func sourcePull(cli command.Cli, namedRef reference.Named, opts PullOptions) error {
	platform := opts.platform
	if platform == "" {
		platform = runtime.GOOS + "/" + runtime.GOARCH
	}

	manifest, err := getSourceManifest(cli, namedRef, platform)
	if err != nil {
		return err
	}

	repoDigest, err := getSourceRepoDigest(manifest, platform)
	if err != nil {
		return err
	}

	// Pull source image located at repoDigest
	srcOptions := PullOptions{
		remote: 	repoDigest,
		all: 		false,
		platform: 	opts.platform,
		untrusted: 	opts.untrusted,
		source:		false,
	}

	return RunPull(cli, srcOptions)
}

func getSourceManifest(cli command.Cli, namedRef reference.Named, platform string) (manifestlist.ManifestDescriptor, error) {
	ctx := context.Background()
	registryClient := cli.RegistryClient(false) // TODO: add flag to PullOptions to allow pulling manifest lists from insecure registries

	// Check remote manifest list
	manifestList, err := registryClient.GetManifestList(ctx, namedRef)
	if err != nil {
		return manifestlist.ManifestDescriptor{}, err
	}
	
	targetRepo, err := registry.ParseRepositoryInfo(namedRef)
	if err != nil {
		return manifestlist.ManifestDescriptor{}, err
	}

	// Resolve desired platform
	clientPlatform, err := platforms.Parse(platform)
	if err != nil {
		return manifestlist.ManifestDescriptor{}, err
	}

	// Check for matching platform in manifest list
	platformMatch := platforms.NewMatcher(clientPlatform)
	for _, img := range manifestList {
		mfd, err := buildManifestDescriptor(targetRepo, img)
		if err != nil {
			return manifestlist.ManifestDescriptor{}, errors.Wrap(err, "failed to assemble ManifestDescriptor")
		}

		if platformMatch.Match(*types.OCIPlatform(&mfd.Platform)) {
			return mfd, nil
		}
	}

	return manifestlist.ManifestDescriptor{}, errors.New("no match for platform " + platform)
}

func getSourceRepoDigest(descriptor manifestlist.ManifestDescriptor, platform string) (string, error) {
	// Obtain RepoDigest for source image
	// TODO: For now it uses the "os-features" field to store the link to source. Eventually this should change
	for _, entry := range descriptor.Platform.OSFeatures {
		if strings.HasPrefix(entry, "source:") {
			return strings.TrimPrefix(entry, "source:"), nil
		}
	}

	return "", errors.New("no source image for platform " + platform)
}

func buildManifestDescriptor(targetRepo *registry.RepositoryInfo, imageManifest types.ImageManifest) (manifestlist.ManifestDescriptor, error) {
	repoInfo, err := registry.ParseRepositoryInfo(imageManifest.Ref)
	if err != nil {
		return manifestlist.ManifestDescriptor{}, err
	}

	manifestRepoHostname := reference.Domain(repoInfo.Name)
	targetRepoHostname := reference.Domain(targetRepo.Name)
	if manifestRepoHostname != targetRepoHostname {
		return manifestlist.ManifestDescriptor{}, errors.Errorf("cannot use source images from a different registry than the target image: %s != %s", manifestRepoHostname, targetRepoHostname)
	}

	manifest := manifestlist.ManifestDescriptor{
		Descriptor: distribution.Descriptor{
			Digest:    imageManifest.Descriptor.Digest,
			Size:      imageManifest.Descriptor.Size,
			MediaType: imageManifest.Descriptor.MediaType,
		},
	}

	platform := types.PlatformSpecFromOCI(imageManifest.Descriptor.Platform)
	if platform != nil {
		manifest.Platform = *platform
	}

	if err = manifest.Descriptor.Digest.Validate(); err != nil {
		return manifestlist.ManifestDescriptor{}, errors.Wrapf(err,
			"digest parse of image %q failed", imageManifest.Ref)
	}

	return manifest, nil
}