# Changelog

## [1.0.1](https://github.com/stfsy/go-envelope-encryption/compare/v1.0.0...v1.0.1) (2026-10-28)


### Features

* **kms:** migrate to AWS SDK for Go v2 and add GCP KMS closer ([0235f7d](https://github.com/stfsy/go-envelope-encryption/commit/0235f7dbd959c9897c371792b6e863e4a3316ab9))


### Bug Fixes

* **envelope:** prevent reload tier downgrade, enforce size limits, and fix auto-reload TOCTOU ([906f8ba](https://github.com/stfsy/go-envelope-encryption/commit/906f8bac69553dc5bca813e361b11243d209a146))
* **keyset:** harden template validation and add context-aware loading ([eea1d1a](https://github.com/stfsy/go-envelope-encryption/commit/eea1d1a20eb9818c2f7f905463a645e3411ca582))
* **lint:** update lint.sh image and resolve static analysis findings ([1d54bde](https://github.com/stfsy/go-envelope-encryption/commit/1d54bdee041edf5dd6775997584d8dd2bf65f1c9))
* **scripts:** fix helper scripts ([2ab2720](https://github.com/stfsy/go-envelope-encryption/commit/2ab2720afc43bd61b0a36ceb7613581a7852782a))


### Miscellaneous Chores

* ignore generated keysets ([f22ec5e](https://github.com/stfsy/go-envelope-encryption/commit/f22ec5e8e3265b9ccd3dcee07e33c83c4ffc4f85))

## [1.0.0](https://github.com/stfsy/go-envelope-encryption/compare/v0.1.0...v1.0.0) (2026-10-26)


### Features

* add module ([62919bc](https://github.com/stfsy/go-envelope-encryption/commit/62919bc378aede3eb06668700b38f054252aec9e))


### Bug Fixes

* resolve staticcheck and errcheck linting errors ([f3c0739](https://github.com/stfsy/go-envelope-encryption/commit/f3c073950aba91b2108730a75cbdf3cebd2d4fbc))


### Miscellaneous Chores

* add license ([1520d75](https://github.com/stfsy/go-envelope-encryption/commit/1520d751f67d765ed54f0ae6afc7f51b0b1047dd))
* **deps:** Bump the all-actions group with 3 updates ([bab536f](https://github.com/stfsy/go-envelope-encryption/commit/bab536f5ba7c91aa8456068c6b6c7ea3e8f7f07a))
* init repo ([8b07971](https://github.com/stfsy/go-envelope-encryption/commit/8b079710e14a579bd584d99f9dfa33fa803b7ffd))
* **release:** release 1.0.0 ([933f41a](https://github.com/stfsy/go-envelope-encryption/commit/933f41a1e207e8c07172b9447f6f8c0081600969))
