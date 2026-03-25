# Changelog
All notable changes to this project will be documented in this file. See [conventional commits](https://www.conventionalcommits.org/) for commit guidelines.

- - -
## [0.2.0](https://github.com/trivy-operator-web-ui/operator/compare/a7ef21caa5f433197963046368382fd235795597..0.2.0) - 2026-03-25
#### Features
- ![BREAKING](https://img.shields.io/badge/BREAKING-red) rename username/password env vars - ([212683e](https://github.com/trivy-operator-web-ui/operator/commit/212683e982738c19773312523507cd609aa19f8a)) - ABWassim
#### Bug Fixes
- http error code ZipSbomError - ([665ccb5](https://github.com/trivy-operator-web-ui/operator/commit/665ccb59664a2ca43954d01173f2eeef7c606f3b)) - ABWassim
#### Documentation
- readme and contributing guidelines - ([60723f5](https://github.com/trivy-operator-web-ui/operator/commit/60723f5ec477573855590911a4d25ee3456522df)) - ABWassim
#### Tests
- cargo format - ([26e4674](https://github.com/trivy-operator-web-ui/operator/commit/26e467425f1231f06eb6f65ed95cc16e22c86b71)) - ABWassim
#### Continuous Integration
- improvements - ([509c9e6](https://github.com/trivy-operator-web-ui/operator/commit/509c9e649a394ab7c1a4c326e7d979073fd5cadc)) - ABWassim
- check commits - ([1c26ad4](https://github.com/trivy-operator-web-ui/operator/commit/1c26ad44747893c7de6afc75efdd36bbd7455794)) - ABWassim
- run tests only when needed - ([a7ef21c](https://github.com/trivy-operator-web-ui/operator/commit/a7ef21caa5f433197963046368382fd235795597)) - ABWassim
#### Miscellaneous Chores
- update chart reference - ([7be5e29](https://github.com/trivy-operator-web-ui/operator/commit/7be5e290ffeaa1712f5afa545d8b1cc6b3b0c18b)) - ABWassim
- bruno - ([f205062](https://github.com/trivy-operator-web-ui/operator/commit/f20506275a26d8f98dac924c211e837f128cb480)) - ABWassim
- license - ([b40644f](https://github.com/trivy-operator-web-ui/operator/commit/b40644ff6193a07ce660790217ecb1f3d0d783c4)) - ABWassim

- - -

## [0.1.1](https://github.com/trivy-operator-web-ui/operator/compare/e41c7633585db796feee744c917a9b3ede019c4c..0.1.1) - 2026-03-23
#### Bug Fixes
- (**sbom**) remove ':' for windows filenames - ([e41c763](https://github.com/trivy-operator-web-ui/operator/commit/e41c7633585db796feee744c917a9b3ede019c4c)) - ABWassim
#### Tests
- update helm chart - ([cd6c480](https://github.com/trivy-operator-web-ui/operator/commit/cd6c48054e66536daebe0b2bd61ed8f3ce403e70)) - ABWassim
#### Miscellaneous Chores
- yaml extension - ([0dbde89](https://github.com/trivy-operator-web-ui/operator/commit/0dbde890d26572454f850812f85391296eba9eb3)) - ABWassim

- - -

## [0.1.0](https://github.com/trivy-operator-web-ui/operator/compare/70c2964a00ace30a4a9326fe1efb44f1eb93adcd..0.1.0) - 2026-03-19
#### Features
- api authentication - ([505b642](https://github.com/trivy-operator-web-ui/operator/commit/505b6421e7930e297153ef51c6fcdbbfd3ae0ea0)) - ABWassim
- lots of - ([4a66605](https://github.com/trivy-operator-web-ui/operator/commit/4a6660521ff73d3b581e1c781237bee7ca249ac1)) - ABWassim
- send severity enum int value instead of string - ([427694d](https://github.com/trivy-operator-web-ui/operator/commit/427694d3e2dcabf486e43b149a31c89600208b17)) - ABWassim
- refactor + route for dedicated vulnreport - ([be7a9b3](https://github.com/trivy-operator-web-ui/operator/commit/be7a9b3628f762845c903a26515982c9436f946e)) - ABWassim
- shared data between operator and API - ([0dbfdfd](https://github.com/trivy-operator-web-ui/operator/commit/0dbfdfd38d3b539c630d7be84ca75f246db513f0)) - ABWassim
- async run webserver and operator - ([558ccd1](https://github.com/trivy-operator-web-ui/operator/commit/558ccd1b7c07771223e061846ecb7fbfbf7ec837)) - ABWassim
#### Bug Fixes
- (**controller**) watch properly for new resources after startup - ([43a1eac](https://github.com/trivy-operator-web-ui/operator/commit/43a1eacd595ee0e3edce40dc2cc3634bef36859c)) - ABWassim
- send image ref instead of report name - ([77a78d9](https://github.com/trivy-operator-web-ui/operator/commit/77a78d93bdbf748804dd638a2592dd66094d431a)) - ABWassim
- testing kube resources + migrate to nginx - ([96525cd](https://github.com/trivy-operator-web-ui/operator/commit/96525cd832b3b969745c528eebddcfdd26e94813)) - ABWassim
#### Tests
- integration tests - ([02487b7](https://github.com/trivy-operator-web-ui/operator/commit/02487b798fbd812f753374d3dc4513ea9c7c0503)) - ABWassim
#### Continuous Integration
- fix cog variable - ([f90e731](https://github.com/trivy-operator-web-ui/operator/commit/f90e7313f30bd0ab2c8b4ece0daed2e94b9fa601)) - ABWassim
- stable identifier for image ref between pr and main - ([300671c](https://github.com/trivy-operator-web-ui/operator/commit/300671c905073b7afd783e4ff790df211a227701)) - ABWassim
#### Refactoring
- one unique stream for controller - ([74c3aff](https://github.com/trivy-operator-web-ui/operator/commit/74c3aff4b49f7fcb2520241ebc2a894503e63ddd)) - ABWassim
#### Miscellaneous Chores
- default logs for api and controller - ([a4c2368](https://github.com/trivy-operator-web-ui/operator/commit/a4c2368b9cc98c0589efd6ff3f227dd4fa73c970)) - ABWassim
- bump dependencies - ([520de0c](https://github.com/trivy-operator-web-ui/operator/commit/520de0c0aec315d231fb39f00401195dbec08a68)) - ABWassim
- bootstrap script for test cluster - ([987e61a](https://github.com/trivy-operator-web-ui/operator/commit/987e61a00f608619f3c5130ffc61966e6b1750bf)) - ABWassim
- lint - ([07bcbd7](https://github.com/trivy-operator-web-ui/operator/commit/07bcbd723f600961a58d1591a1fc83cc9f671e39)) - ABWassim
- dockerfile for proxy - ([80b0f3b](https://github.com/trivy-operator-web-ui/operator/commit/80b0f3bb9d2502c633132b9b8986c6db0abbbe2a)) - ABWassim
- local ingress with rancher + traefik - ([56e5673](https://github.com/trivy-operator-web-ui/operator/commit/56e5673dcbca6659d8bbaa58358db96a9b57e6ef)) - ABWassim
- state of the art - ([386cb5c](https://github.com/trivy-operator-web-ui/operator/commit/386cb5ca892e63ae08a85198333bf81850b2f116)) - ABWassim

- - -

Changelog generated by [cocogitto](https://github.com/cocogitto/cocogitto).