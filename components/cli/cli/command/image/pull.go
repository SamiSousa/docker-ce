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
	remote    	string
	all       	bool
	platform  	string
	untrusted 	bool
	insecure 	bool
	source 		bool
	binary		bool
	reference 	string
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
	flags.BoolVar(&opts.insecure, "insecure", false, "Allow communication with an insecure registry")
	flags.BoolVar(&opts.source, "source", false, "Download source for an image")
	flags.BoolVar(&opts.binary, "binary", false, "Download binary for a source image")
	flags.StringVar(&opts.reference, "reference", "", "Download a specified reference from an image. Eg 'source' or 'binary'")

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
	case opts.source && opts.binary:
		return errors.New("can't use --source with --binary")
	case opts.source && opts.reference != "":
		return errors.New("--reference can't be used with --source")
	case opts.binary && opts.reference != "":
		return errors.New("--reference can't be used with --binary")
	case opts.all && (opts.source || opts.binary || (opts.reference != "")):
		switch {
		case opts.source:
			return errors.New("can't use --source with --all-tags/-a")
		case opts.binary:
			return errors.New("can't use --binary with --all-tags/-a")
		case opts.reference != "":
			return errors.New("can't use --reference with --all-tags/-a")
		}
	case !opts.all && reference.IsNameOnly(distributionRef):
		distributionRef = reference.TagNameOnly(distributionRef)
		if tagged, ok := distributionRef.(reference.Tagged); ok {
			fmt.Fprintf(cli.Out(), "Using default tag: %s\n", tagged.Tag())
		}
	}

	// Check if a reference flag is passed
	if opts.source {
		opts.reference = "source"
	} else if opts.binary {
		opts.reference = "binary"
	}
	if opts.reference != "" {
		return referencePull(cli, distributionRef, opts)
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

// referencePull attempts to pull an image reference in the manifest list
func referencePull(cli command.Cli, namedRef reference.Named, opts PullOptions) error {
	platform := opts.platform
	if platform == "" {
		platform = runtime.GOOS + "/" + runtime.GOARCH
	}

	manifest, err := getImageManifest(cli, namedRef, platform, opts.insecure)
	if err != nil {
		return err
	}

	repoDigest, err := getReferenceRepoDigest(manifest, platform, opts.reference)
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
		binary:		false,
		reference:	"",
		insecure:	opts.insecure,
	}

	return RunPull(cli, srcOptions)
}

func getImageManifest(cli command.Cli, namedRef reference.Named, platform string, insecure bool) (manifestlist.ManifestDescriptor, error) {
	ctx := context.Background()

	// TODO: add flag to PullOptions to allow pulling manifest lists from insecure registries
	registryClient := cli.RegistryClient(insecure)

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

func getReferenceRepoDigest(descriptor manifestlist.ManifestDescriptor, platform string, reference string) (string, error) {
	// Obtain RepoDigest for reference image
	// TODO: For now it uses the "os-features" field to store the reference. Eventually this should change
	for _, entry := range descriptor.Platform.OSFeatures {
		if strings.HasPrefix(entry, reference + ":") {
			return strings.TrimPrefix(entry, reference + ":"), nil
		}
	}

	return "", errors.New("no reference " + reference + " for platform " + platform)
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