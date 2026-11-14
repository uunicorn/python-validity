#!/bin/bash
VERSION="0.15"

sudo dnf install rpm-build rpmdevtools python3-devel checkpolicy policycoreutils bzip2 innoextract

rpmdev-setuptree

git archive --format=tar.gz --prefix="python-validity-$VERSION/" -o "$HOME/rpmbuild/SOURCES/python-validity-$VERSION.tar.gz" HEAD

cp python-validity.spec ~/rpmbuild/SPECS

sudo dnf builddep ~/rpmbuild/SPECS/python-validity.spec

rpmbuild -ba ~/rpmbuild/SPECS/python-validity.spec
