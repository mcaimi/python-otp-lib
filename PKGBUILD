# Maintainer: Marco Caimi <mcaimi@redhat.com>
_pkgname=otp-lib
pkgname=python-${_pkgname}-git
pkgver=0.1
pkgrel=1
pkgdesc="Python package for generating HOTP and TOTP tokens."
depends=('python')
makedepends=('python-pytest')
optdepends=()
license=('GPL')
arch=('any')

_gitremote="https://github.com/mcaimi/python-otp-lib.git"
_gitpath="python-${_pkgname}"

build() {
  if [ -d $_gitpath ]; then
    cd $_gitpath && git pull
  else
    git clone $_gitremote $_gitpath
  fi

  msg "GIT pull complete, starting build..."
  cd $srcdir/$_gitpath
  python setup.py build

  msg "Testing..."
  cd $srcdir/$_gitpath
  pytest
}

package() {
  msg "starting package().."
  cd $srcdir/$_gitpath
  python setup.py install --root="$pkgdir" --optimize=1
}

