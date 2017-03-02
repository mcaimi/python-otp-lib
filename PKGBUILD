# Maintainer: Marco Caimi <marco.caimi@fastweb.it>
_pkgname=fastwebotp
pkgname=python-${_pkgname}-git
pkgver=0.1
pkgrel=1
pkgdesc="Python package for generating HOTP and TOTP tokens."
depends=('python')
optdepends=()
license=('GPL')
arch=('any')

_gitremote="git@mi-ber-vlgit01.dev.fastcloud.fwb:mcaimi/python-otp-lib.git"
_gitpath="python-fastwebotp"

build() {
  if [ -d $_gitpath ]; then
    cd $_gitpath && git pull
  else
    git clone $_gitremote $_gitpath
  fi

  msg "GIT pull complete, starting build..."
  cd $srcdir/$_gitpath
  python setup.py build
}

package() {
  msg "starting package().."
  cd $srcdir/$_gitpath
  python setup.py install --root="$pkgdir" --optimize=1
}

