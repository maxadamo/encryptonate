#!/bin/bash
set -x
set -e

package_version=`cat VERSION`

rm -f *.deb

fpm -t deb \
    -s dir \
    --architecture all \
    --version ${package_version} \
    --after-install post-install.sh \
    --maintainer 'Jenkins Blahblah <blahblah@domain.com>' \
    --deb-user root \
    --deb-group root \
    --description 'encryptonate' \
    --verbose \
    -C . \
    -x post-install.sh \
    -x README.md \
    -x run_fpm.sh \
    -x VERSION \
    -x .git \
    -x *.deb \
    --deb-pre-depends python-rsa \
    --deb-pre-depends python-crypto \
    --deb-pre-depends python-gnupg \
    --name encryptonate \
    .
