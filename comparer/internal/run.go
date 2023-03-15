package internal

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

const (
	left  rune = '<'
	right rune = '>'
)

type hdrContent struct {
	*tar.Header
	sha []byte
}

type differ struct {
	file      string
	diffs     []string
	leftOnly  bool
	rightOnly bool
}

func (d differ) String() string {
	if d.leftOnly {
		return fmt.Sprintf("%c %s", left, d.file)
	}
	if d.rightOnly {
		return fmt.Sprintf("%c %s", right, d.file)
	}
	return fmt.Sprintf("  %s (%v)", d.file, strings.Join(d.diffs, ", "))
}

func Run(nameA, nameB string, params Params) error {
	// first get manifests for each image
	imagesA, err := refToImages(nameA, params)
	if err != nil {
		return err
	}
	if len(imagesA) == 0 && params.IgnoreMissingImage {
		log.Debugf("image %s not found, told to ignore, no error", nameA)
		return nil
	}
	log.Debugf("resolved %s to %v", nameA, imagesA)
	imagesB, err := refToImages(nameB, params)
	if err != nil {
		return err
	}
	if len(imagesB) == 0 && params.IgnoreMissingImage {
		log.Debugf("image %s not found, told to ignore, no error", nameB)
		return nil
	}
	log.Debugf("resolved %s to %v", nameB, imagesB)
	platforms := params.Platforms
	if len(platforms) == 0 {
		pMap := map[string]bool{}
		for p := range imagesA {
			pMap[p] = true
		}
		for p := range imagesB {
			pMap[p] = true
		}
		for p := range pMap {
			platforms = append(platforms, p)
		}
	}
	for _, p := range platforms {
		var (
			w io.Writer
		)
		w = os.Stdout
		filename := "stdout"
		if params.SaveFilePattern != "" {
			filename = params.SaveFilePattern
			dir := filepath.Dir(filename)
			base := filepath.Base(filename)
			base = strings.Replace(base, "IMAGE", fmt.Sprintf("%s-%s", nameA, nameB), -1)
			base = strings.Replace(base, "PLATFORM", p, -1)
			base = strings.ReplaceAll(base, "/", "_")
			base = strings.ReplaceAll(base, ":", "_")
			filename = filepath.Join(dir, base)
			f, err := os.Create(filename)
			if err != nil {
				return fmt.Errorf("unable to open file %s: %v", filename, err)
			}
			w = f
			defer f.Close()
		}
		log.Debugf("Comparing platform %s", p)
		imgA, ok := imagesA[p]
		if !ok {
			log.Printf("Platform %s not found in %s", p, nameA)
			continue
		}
		imgB, ok := imagesB[p]
		if !ok {
			log.Printf("Platform %s not found in %s", p, nameB)
			continue
		}
		log.Debugf("writing output to %s", filename)
		// create a map of each, so we can compare
		fullA := map[string]*hdrContent{}
		fullB := map[string]*hdrContent{}
		rA, wA := io.Pipe()
		rB, wB := io.Pipe()
		var errg errgroup.Group
		errg.Go(exportMaker(wA, imgA))
		errg.Go(exportMaker(wB, imgB))
		errg.Go(mapMaker(rA, fullA))
		errg.Go(mapMaker(rB, fullB))
		if err := errg.Wait(); err != nil {
			return err
		}
		// now can compare the maps
		var (
			results []*differ
			sorted  []string
			both    = map[string]bool{}
		)
		for k := range fullA {
			both[k] = true
		}
		for k := range fullB {
			both[k] = true
		}
		for k := range both {
			sorted = append(sorted, k)
		}
		sort.StringSlice(sorted).Sort()
		for _, path := range sorted {
			var (
				differences   []string
				ignoreSize    = params.IgnoreSize
				ignoreContent = params.IgnoreContent
			)
			infoA, okA := fullA[path]
			infoB, okB := fullB[path]
			if okA && !okB {
				if params.IgnoreExtraFiles != ImageBoth && params.IgnoreExtraFiles != ImageLeft {
					results = append(results, &differ{file: path, leftOnly: true})
				}
				continue
			}
			if !okA && okB {
				if params.IgnoreExtraFiles != ImageBoth && params.IgnoreExtraFiles != ImageRight {
					results = append(results, &differ{file: path, rightOnly: true})
				}
				continue
			}
			if infoA.Typeflag != infoB.Typeflag {
				differences = append(differences, fmt.Sprintf("file type %c%v %c%v", left, infoA.Typeflag, right, infoB.Typeflag))
				// ignore size and content if the type is different
				ignoreSize = true
				ignoreContent = true
			}
			if infoA.Typeflag == tar.TypeSymlink {
				if infoA.Linkname != infoB.Linkname {
					differences = append(differences, fmt.Sprintf("symlink target %c%v %c%v", left, infoA.Linkname, right, infoB.Linkname))
				}
				ignoreContent = true
				ignoreSize = true
			}
			if !ignoreSize {
				if infoA.Size != infoB.Size {
					differences = append(differences, fmt.Sprintf("size %c%d %c%d", left, infoA.Size, right, infoB.Size))
				}
			}
			if !ignoreContent {
				if !bytes.Equal(infoA.sha, infoB.sha) {
					differences = append(differences, "content")
				}
			}
			if !params.IgnoreTimestamps {
				if infoA.ModTime != infoB.ModTime {
					differences = append(differences, fmt.Sprintf("timestamps %c%v %c%v", left, infoA.ModTime, right, infoB.ModTime))
				}
			}
			if !params.IgnorePermissions {
				if infoA.Mode != infoB.Mode {
					differences = append(differences, fmt.Sprintf("permissions %c%v %c%v", left, infoA.Mode, right, infoB.Mode))
				}
			}
			if !params.IgnoreOwnership {
				if infoA.Uid != infoB.Uid || infoA.Gid != infoB.Gid {
					differences = append(differences, fmt.Sprintf("ownership %c%v:%v %c%v:%v", left, infoA.Uid, infoA.Gid, right, infoB.Uid, infoB.Gid))
				}
			}

			if len(differences) > 0 {
				results = append(results, &differ{file: path, diffs: differences})
			}
		}
		if len(results) == 0 {
			fmt.Fprintf(w, "%s identical\n", p)
		} else {
			fmt.Fprintf(w, "%s differs:\n", p)
			for _, r := range results {
				fmt.Fprintln(w, r.String())
			}
		}
		fmt.Fprintln(w)
	}
	return nil
}

func refToImages(imgName string, p Params) (map[string]v1.Image, error) {
	// first get manifests for each image
	images := map[string]v1.Image{}
	ref, err := name.ParseReference(imgName)
	if err != nil {
		return images, err
	}
	_, _, options := apiOptions(p)
	manifest, err := remote.Get(ref, options...)
	if err != nil {
		// if it was not found and we were told to ignore such errors, return no error
		var e *transport.Error
		if errors.As(err, &e) && e.StatusCode == 404 && p.IgnoreMissingImage {
			return images, nil
		}

		return images, err
	}
	// try getting it as an index, if not, then as an image
	index, err := manifest.ImageIndex()
	if err == nil {
		idx, err := index.IndexManifest()
		if err != nil {
			return images, fmt.Errorf("%s was index, but could not resolve components of index: %w", imgName, err)
		}
		for _, m := range idx.Manifests {
			img, err := index.Image(m.Digest)
			if err != nil {
				return images, fmt.Errorf("%s was index, but could not resolve component %s of index: %w", imgName, m.Platform, err)
			}
			images[m.Platform.String()] = img
		}
	} else {
		// try getting it as an image
		image, err := manifest.Image()
		if err != nil {
			return images, fmt.Errorf("%s is neither image nor index: %w", imgName, err)
		}
		cfgFile, err := image.ConfigFile()
		if err != nil {
			return images, fmt.Errorf("%s is image, but could not get config file: %w", imgName, err)
		}
		platform := v1.Platform{
			Architecture: cfgFile.Architecture,
			OS:           cfgFile.OS,
			OSVersion:    cfgFile.OSVersion,
		}
		images[platform.String()] = image
	}
	return images, nil
}

func mapMaker(r io.ReadCloser, m map[string]*hdrContent) func() error {
	return func() error {
		defer r.Close()
		tr := tar.NewReader(r)
		for {
			hdr, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				return err
			}
			// get the hash of the file content
			h := sha256.New()
			if _, err := io.Copy(h, tr); err != nil {
				return fmt.Errorf("unable to hash %s: %w", hdr.Name, err)
			}
			m[hdr.Name] = &hdrContent{
				Header: hdr,
				sha:    h.Sum(nil),
			}
		}
		return nil
	}
}

func exportMaker(w io.WriteCloser, img v1.Image) func() error {
	return func() error {
		defer w.Close()
		return crane.Export(img, w)
	}
}

func apiOptions(p Params) (bool, string, []remote.Option) {
	var (
		options = []remote.Option{}
		msg     []string
	)

	switch {
	case p.Anonymous:
		msg = append(msg, "Anonymous auth")
		options = append(options, remote.WithAuth(authn.Anonymous))
	case p.Username != "" || p.Password != "":
		msg = append(msg, "username password auth")
		options = append(options, remote.WithAuth(authn.FromConfig(authn.AuthConfig{Username: p.Username, Password: p.Password})))
	case !p.Anonymous:
		msg = append(msg, "default keychain auth")
		options = append(options, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	case p.Proxy != "":
		msg = append(msg, "custom http.Client with proxy")
		proxy, err := url.Parse(p.Proxy)
		if err != nil {
			log.Fatalf("invalid proxy URL %s: %v", p.Proxy, err)
		}
		tr := &http.Transport{
			Proxy: http.ProxyURL(proxy),
		}
		options = append(options, remote.WithTransport(tr))
	}
	return false, strings.Join(msg, " "), options
}
