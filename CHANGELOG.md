# Changelog

## [0.8.0](https://github.com/tomatoaiu/agent-command-guard/compare/v0.7.0...v0.8.0) (2026-08-24)


### Features

* let an agent write its own user-scope skills ([#56](https://github.com/tomatoaiu/agent-command-guard/issues/56)) ([ebad0a1](https://github.com/tomatoaiu/agent-command-guard/commit/ebad0a10bc621f246f29e55606865d8d4edf7aac))

## [0.7.0](https://github.com/tomatoaiu/agent-command-guard/compare/v0.6.4...v0.7.0) (2026-08-23)


### Features

* add repository-scoped pull request blocks ([#54](https://github.com/tomatoaiu/agent-command-guard/issues/54)) ([7555fc5](https://github.com/tomatoaiu/agent-command-guard/commit/7555fc5593c82c07a492239b5e2e5bae5bcf6f1a))

## [0.6.4](https://github.com/tomatoaiu/agent-command-guard/compare/v0.6.3...v0.6.4) (2026-08-19)


### Bug Fixes

* stop reviewing a git clean that only lists what it would remove ([#51](https://github.com/tomatoaiu/agent-command-guard/issues/51)) ([c169374](https://github.com/tomatoaiu/agent-command-guard/commit/c169374fa0c4f5d491e1cc16913bd256565476aa))

## [0.6.3](https://github.com/tomatoaiu/agent-command-guard/compare/v0.6.2...v0.6.3) (2026-08-19)


### Bug Fixes

* inspect find -exec commands and stop misreading a bare dash ([#49](https://github.com/tomatoaiu/agent-command-guard/issues/49)) ([91ddd33](https://github.com/tomatoaiu/agent-command-guard/commit/91ddd33383584ac99b50b0c6ade13cf76ad99a86))

## [0.6.2](https://github.com/tomatoaiu/agent-command-guard/compare/v0.6.1...v0.6.2) (2026-08-18)


### Bug Fixes

* protect the agent control surface instead of the whole directory ([#46](https://github.com/tomatoaiu/agent-command-guard/issues/46)) ([c178910](https://github.com/tomatoaiu/agent-command-guard/commit/c178910987af767cdd4ee077bbd7824b20dae82c))
* read inline interpreter payloads and name the rule in every decision ([#48](https://github.com/tomatoaiu/agent-command-guard/issues/48)) ([5c2699a](https://github.com/tomatoaiu/agent-command-guard/commit/5c2699a84f0d1bef7f19e8737b42fab723888826))

## [0.6.1](https://github.com/tomatoaiu/agent-command-guard/compare/v0.6.0...v0.6.1) (2026-08-18)


### Bug Fixes

* apply the protected-target decision regardless of the verb ([#43](https://github.com/tomatoaiu/agent-command-guard/issues/43)) ([72f8153](https://github.com/tomatoaiu/agent-command-guard/commit/72f815378b238685fc85f38c42917b2f3bc2e156))
* resolve values built from names assigned earlier ([#45](https://github.com/tomatoaiu/agent-command-guard/issues/45)) ([b79be07](https://github.com/tomatoaiu/agent-command-guard/commit/b79be07aae867d41bfb8d70c77ffbd4a08d23471))

## [0.6.0](https://github.com/tomatoaiu/agent-command-guard/compare/v0.5.3...v0.6.0) (2026-08-18)


### Features

* guard package publication, repository teardown, and data exposure ([#42](https://github.com/tomatoaiu/agent-command-guard/issues/42)) ([3d8da7d](https://github.com/tomatoaiu/agent-command-guard/commit/3d8da7d6c37fe678bac3cf6e92740163973e32ea))
* guard privilege escalation, storage destruction, and service changes ([#41](https://github.com/tomatoaiu/agent-command-guard/issues/41)) ([c2e8297](https://github.com/tomatoaiu/agent-command-guard/commit/c2e82971eb7795f0bb213d7e726946d6069111ae))


### Bug Fixes

* judge chmod, csrutil, dscl, and networksetup by their arguments ([#39](https://github.com/tomatoaiu/agent-command-guard/issues/39)) ([d38e4ca](https://github.com/tomatoaiu/agent-command-guard/commit/d38e4ca089679001d9f17487fdd74df86ca7d472))

## [0.5.3](https://github.com/tomatoaiu/agent-command-guard/compare/v0.5.2...v0.5.3) (2026-08-18)


### Bug Fixes

* allow read-only nvram invocations and block only writes ([#35](https://github.com/tomatoaiu/agent-command-guard/issues/35)) ([8c2878d](https://github.com/tomatoaiu/agent-command-guard/commit/8c2878da4a3745cf08e58b176477d7a039cc8a3a))

## [0.5.2](https://github.com/tomatoaiu/agent-command-guard/compare/v0.5.1...v0.5.2) (2026-08-18)


### Bug Fixes

* resolve literal assignments and fixed xargs payloads ([#33](https://github.com/tomatoaiu/agent-command-guard/issues/33)) ([8e72ded](https://github.com/tomatoaiu/agent-command-guard/commit/8e72dedb1b29b22c66ef7d84a2d23518b2ff2d0e))

## [0.5.1](https://github.com/tomatoaiu/agent-command-guard/compare/v0.5.0...v0.5.1) (2026-08-17)


### Bug Fixes

* treat linked worktrees and the memory store as inside the workspace ([#31](https://github.com/tomatoaiu/agent-command-guard/issues/31)) ([06c9064](https://github.com/tomatoaiu/agent-command-guard/commit/06c90647a6dbee3e0207010e6ecf7e9dd0d89d99))

## [0.5.0](https://github.com/tomatoaiu/agent-command-guard/compare/v0.4.0...v0.5.0) (2026-08-17)


### Features

* add scoped suppression for built-in findings ([#29](https://github.com/tomatoaiu/agent-command-guard/issues/29)) ([ccc45d5](https://github.com/tomatoaiu/agent-command-guard/commit/ccc45d5f9f07258253b16c7c25dbf1301c7e3378))

## [0.4.0](https://github.com/tomatoaiu/agent-command-guard/compare/v0.3.0...v0.4.0) (2026-08-15)


### Features

* explain ineligible protected branch exceptions ([#27](https://github.com/tomatoaiu/agent-command-guard/issues/27)) ([da9718d](https://github.com/tomatoaiu/agent-command-guard/commit/da9718de67cfa4d9270ae1ee4a724c8dadb3e9b1))

## [0.3.0](https://github.com/tomatoaiu/agent-command-guard/compare/v0.2.0...v0.3.0) (2026-08-14)


### Features

* add scoped direct file rules ([#25](https://github.com/tomatoaiu/agent-command-guard/issues/25)) ([a38e7fb](https://github.com/tomatoaiu/agent-command-guard/commit/a38e7fbf7da4f4528fac995b120670f92894e7ad))

## [0.2.0](https://github.com/tomatoaiu/agent-command-guard/compare/v0.1.0...v0.2.0) (2026-08-14)


### Features

* add direct file and structured Git policies ([#22](https://github.com/tomatoaiu/agent-command-guard/issues/22)) ([0cee999](https://github.com/tomatoaiu/agent-command-guard/commit/0cee999cadbdca4ac7bbc6721739203bc34ad7d2))

## 0.1.0 (2026-08-13)


### Features

* add Windows support and release builds ([#19](https://github.com/tomatoaiu/agent-command-guard/issues/19)) ([edc9e6c](https://github.com/tomatoaiu/agent-command-guard/commit/edc9e6c3098f0daa6a2292e910da4718a5b04374))


### Bug Fixes

* **release:** start versioning at 0.1.0 ([#21](https://github.com/tomatoaiu/agent-command-guard/issues/21)) ([8791cab](https://github.com/tomatoaiu/agent-command-guard/commit/8791cabc1794285bfe56fd89f46070214ae68b32))
