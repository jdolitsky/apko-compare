#!/bin/bash

set -e

WOLFI_OS=$GOPATH/src/github.com/wolfi-dev/os
REPO=https://packages.wolfi.dev/os
KEYFILE=local-melange.rsa

cd ${WOLFI_OS}

if [ ! -f ${KEYFILE} -o ! -f ${KEYFILE}.pub ]; then
	rm -f ${KEYFILE} ${KEYFILE}.pub
	melange keygen ${KEYFILE}
fi
packages="$@"
if [ -z "${packages}" ]; then
	packages=$(wolfictl text -d . -t name)
fi

# because of bootstrapping stuff
packages="openssl ${packages}"

# build and pull down all packages
for package in ${packages}; do
	file=${package}.yaml
	# get version from yaml file
	version=$(melange package-version ${file})
	arches="aarch64 x86_64"
	for arch in $arches; do
		# build
		echo "Building ${version}"
		melange build ${file} --repository-append $(pwd)/packages --keyring-append ${KEYFILE}.pub --signing-key ${KEYFILE} --arch ${arch} --env-file build-${arch}.env --namespace wolfi --generate-index false  --source-dir ./${package}/ --runner docker
		# pull
		pulled=$(pwd)/packages/pulled
		mkdir -p ${pulled}/${arch}
		echo "Pulling ${version}"
		curl -L ${REPO}/${arch}/${version}.apk > ${pulled}/${arch}/${version}.apk
	done
done

