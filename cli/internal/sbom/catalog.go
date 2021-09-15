package sbom

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/presenter/packages"
	"github.com/anchore/syft/syft/source"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/sirupsen/logrus"
)

const cachePath = ".image-cache"
const imageSbomScope = source.AllLayersScope

/**
CatalogPackagesInImages takes a list of image tags that exist within the tarred collection
of images located at imageTarballPath and generates an SBOM for each one. Each generated
SBOM will be saved in the provided sbomDir as `.zarf-sbom-<IMAGE ID>.json`.
**/
func CatalogPackagesInImages(imgTags []string, imageTarballPath string, sbomDir string) {
	logrus.Info("Creating SBOM for images")
	for _, tag := range imgTags {
		img, err := crane.LoadTag(imageTarballPath, tag)
		if err != nil {
			logrus.Fatalf("Unable to load the image metadata")
		}

		i := image.NewImage(img, cachePath, image.WithTags(tag))
		if err = i.Read(); err != nil {
			logrus.Fatalf("Unable to read the tarred image")
		}

		src, err := source.NewFromImage(i, "")
		if err != nil {
			logrus.Fatal("Unable to create the SBOM")
		}

		catalog, distro, err := syft.CatalogPackages(&src, imageSbomScope)
		presenter := packages.Presenter(packages.JSONPresenterOption, packages.PresenterConfig{
			SourceMetadata: src.Metadata,
			Catalog:        catalog,
			Distro:         distro,
			Scope:          imageSbomScope,
		})

		f, err := os.Create(getSbomFileName(sbomDir, src.Metadata.ImageMetadata.ID))
		if err != nil {
			logrus.Fatal("Failed to create SBOM file")
		}

		defer f.Close()
		if err = presenter.Present(f); err != nil {
			logrus.Fatal("Failed to write SBOM file")
		}
	}
}

func getSbomFileName(sbomDir, imgId string) string {
	return filepath.Join(sbomDir, fmt.Sprintf(".zarf-sbom-%v.json", imgId))
}
