package manifest

import (
	"errors"
	"context"

	"github.com/docker/cli/cli"
	"github.com/docker/cli/cli/command"
	"github.com/docker/cli/cli/manifest/types"
	"github.com/docker/distribution/reference"
	"github.com/opencontainers/go-digest"
	"github.com/spf13/cobra"
)

type sourceOpts struct {
	amend    		bool
	insecure 		bool
	image 	 		string
	source 	 		string
	only_binary 	bool
	manifest_list 	string
	source_list  	string
}

func newSourceListCommand(dockerCli command.Cli) *cobra.Command {
	opts := sourceOpts{}

	cmd := &cobra.Command{
		Use:   "source MANIFEST SOURCE",
		Short: "Create a pair of local manifest lists with a reference to SOURCE and MANIFEST for annotating and pushing to a registry",
		Args:  cli.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.image = args[0]
			opts.source = args[1]
			return sourceManifestList(dockerCli, opts)
		},
	}

	flags := cmd.Flags()
	flags.BoolVar(&opts.insecure, "insecure", false, "Allow communication with an insecure registry")
	flags.BoolVarP(&opts.amend, "amend", "a", false, "Amend an existing manifest list")
	flags.BoolVarP(&opts.only_binary, "only-binary", "b", false, "Only create binary manifest list for referencing source")
	flags.StringVar(&opts.manifest_list, "manifest-list", "", "Set name for created manifest list")
	flags.StringVar(&opts.source_list, "source-list", "", "Set name for created source manifest list")
	return cmd
}

func sourceManifestList(dockerCli command.Cli, opts sourceOpts) error {
	
	// Verify that each image exists in the registry,
	// while getting the RepoDigests for each image
	imageRepoDigest, err := getRepoDigest(dockerCli, opts.image, opts.manifest_list, opts)
	if err != nil {
		return err
	}

	sourceRepoDigest, err := getRepoDigest(dockerCli, opts.source, opts.source_list, opts)
	if err != nil {
		return err
	}

	err = createManifestListWrapper(dockerCli, opts.manifest_list, opts.image, opts)
	if err != nil {
		return err
	}

	if !opts.only_binary {
		// Create the source manifest list
		err = createManifestListWrapper(dockerCli, opts.source_list, opts.source, opts)
		if err != nil {
			return err
		}
		
		// Add binary reference to source's manifest list
		err = runManifestAnnotateWrapper(dockerCli, opts.source_list, opts.source, "binary:" + imageRepoDigest)
		if err != nil {
			return err
		}
	}

	// Add source reference to image's manifest list
	return runManifestAnnotateWrapper(dockerCli, opts.manifest_list, opts.image, "source:" + sourceRepoDigest)
}

func createManifestListWrapper(dockerCli command.Cli, list string, image string, opts sourceOpts) error {
	// Create a manifest list
	if list == "" {
		list = image
		dockerCli.Out().Write([]byte("Using manifest list name " + list + " for image " + image + "\n"))
	}

	listArgs := []string{list, image}

	listOptions := createOpts{
		amend: opts.amend,
		insecure: opts.insecure,
	}

	return createManifestList(dockerCli, listArgs, listOptions)
}

func runManifestAnnotateWrapper(dockerCli command.Cli, list string, image string, repoDigest string) error {
	if list == "" {
		list = image
	}

	annotateOpts := annotateOptions {
		target: list,
		image: image,
		variant: "",
		os: "",
		arch: "",
		osFeatures: []string{
			repoDigest,
		},
	}

	return runManifestAnnotate(dockerCli, annotateOpts)
}

func getRepoDigest(dockerCli command.Cli, ref string, list string, opts sourceOpts) (string, error) {
	namedRef, err := normalizeReference(ref)
	if err != nil {
		return "", err
	}

	// If list reference is provided, display the local manifest in a list
	if list != "" {
		listRef, err := normalizeReference(list)
		if err != nil {
			return "", err
		}

		imageManifest, err := dockerCli.ManifestStore().Get(listRef, namedRef)
		if err != nil {
			return "", err
		}
		return makeRepoDigest(imageManifest)
	}

	// Try a local manifest list first
	localManifestList, err := dockerCli.ManifestStore().GetList(namedRef)
	if err == nil {
		return makeRepoDigestFromList(namedRef, localManifestList)
	}

	// Next try a remote manifest
	ctx := context.Background()
	registryClient := dockerCli.RegistryClient(opts.insecure)
	imageManifest, err := registryClient.GetManifest(ctx, namedRef)
	if err == nil {
		return makeRepoDigest(imageManifest)
	}

	// Finally try a remote manifest list
	manifestList, err := registryClient.GetManifestList(ctx, namedRef)
	if err != nil {
		return "", err
	}
	return makeRepoDigestFromList(namedRef, manifestList)
}

func makeRepoDigest(man types.ImageManifest) (string, error) {
	name, err := reference.WithName(man.Ref.Name())
	if err != nil {
		return "", err
	}

	digest, err := digest.Parse(man.Descriptor.Digest.String())
	if err != nil {
		return "", err
	}

	namedDigest, err := reference.WithDigest(name, digest)
	if err != nil {
		return "", err
	}

	return namedDigest.String(), nil
}

func makeRepoDigestFromList(namedRef reference.Named, mans []types.ImageManifest) (string, error) {
	// Case of one list entry, use that entry
	if len(mans) == 1 {
		return makeRepoDigest(mans[0])
	}

	// Find match for namedRef in list
	for _, man := range mans {
		manName, err := reference.WithName(man.Ref.Name())
		if err != nil {
			return "", err
		}

		if manName.String() == namedRef.String() {
			return makeRepoDigest(man)
		}
	}

	// No matching entry in manifest list
	return "", errors.New("no matching entries in manifest list for " + namedRef.String())
}
