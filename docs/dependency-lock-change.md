# Dependency Lock Change

The public workspace was reduced to its 13 supported crates. Regenerating the
lockfile then removed dependencies reachable only from excluded crates and
selected the newest registry versions compatible with the retained manifest
constraints. This file records the exact package-record delta.

- Exported lock SHA-256: `da0ca207eb298b64c40f86f3c7db86112796792d087a164c09f63e38c1026587`
- Current lock SHA-256: `708758b18e244ddedd0750872bd72bfafca7430aa31d54edcb8440ba175fcad1`
- Removed package records: 162
- Added package records: 80

A remove/add pair with the same package name is a version update.

## Removed package records

| Package | Version | Source |
|---|---:|---|
| anstream | 1.0.0 | registry+https://github.com/rust-lang/crates.io-index |
| anstyle | 1.0.14 | registry+https://github.com/rust-lang/crates.io-index |
| anstyle-parse | 1.0.0 | registry+https://github.com/rust-lang/crates.io-index |
| anstyle-query | 1.1.5 | registry+https://github.com/rust-lang/crates.io-index |
| anstyle-wincon | 3.0.11 | registry+https://github.com/rust-lang/crates.io-index |
| anyhow | 1.0.102 | registry+https://github.com/rust-lang/crates.io-index |
| autocfg | 1.5.0 | registry+https://github.com/rust-lang/crates.io-index |
| bitflags | 2.11.0 | registry+https://github.com/rust-lang/crates.io-index |
| block-buffer | 0.10.4 | registry+https://github.com/rust-lang/crates.io-index |
| bumpalo | 3.20.2 | registry+https://github.com/rust-lang/crates.io-index |
| bytes | 1.11.1 | registry+https://github.com/rust-lang/crates.io-index |
| cc | 1.2.56 | registry+https://github.com/rust-lang/crates.io-index |
| chrono | 0.4.44 | registry+https://github.com/rust-lang/crates.io-index |
| clap | 4.6.0 | registry+https://github.com/rust-lang/crates.io-index |
| clap_builder | 4.6.0 | registry+https://github.com/rust-lang/crates.io-index |
| clap_derive | 4.6.0 | registry+https://github.com/rust-lang/crates.io-index |
| clap_lex | 1.1.0 | registry+https://github.com/rust-lang/crates.io-index |
| colorchoice | 1.0.5 | registry+https://github.com/rust-lang/crates.io-index |
| cpufeatures | 0.2.17 | registry+https://github.com/rust-lang/crates.io-index |
| crypto-common | 0.1.7 | registry+https://github.com/rust-lang/crates.io-index |
| digest | 0.10.7 | registry+https://github.com/rust-lang/crates.io-index |
| displaydoc | 0.2.5 | registry+https://github.com/rust-lang/crates.io-index |
| fastrand | 2.3.0 | registry+https://github.com/rust-lang/crates.io-index |
| foldhash | 0.1.5 | registry+https://github.com/rust-lang/crates.io-index |
| generic-array | 0.14.7 | registry+https://github.com/rust-lang/crates.io-index |
| getrandom | 0.4.1 | registry+https://github.com/rust-lang/crates.io-index |
| h2 | 0.4.13 | registry+https://github.com/rust-lang/crates.io-index |
| hashbrown | 0.15.5 | registry+https://github.com/rust-lang/crates.io-index |
| hashbrown | 0.16.1 | registry+https://github.com/rust-lang/crates.io-index |
| heck | 0.5.0 | registry+https://github.com/rust-lang/crates.io-index |
| http | 1.4.0 | registry+https://github.com/rust-lang/crates.io-index |
| http-body | 1.0.1 | registry+https://github.com/rust-lang/crates.io-index |
| http-body-util | 0.1.3 | registry+https://github.com/rust-lang/crates.io-index |
| http-range-header | 0.4.2 | registry+https://github.com/rust-lang/crates.io-index |
| hyper | 1.8.1 | registry+https://github.com/rust-lang/crates.io-index |
| hyper-rustls | 0.27.7 | registry+https://github.com/rust-lang/crates.io-index |
| icu_collections | 2.1.1 | registry+https://github.com/rust-lang/crates.io-index |
| icu_locale_core | 2.1.1 | registry+https://github.com/rust-lang/crates.io-index |
| icu_normalizer | 2.1.1 | registry+https://github.com/rust-lang/crates.io-index |
| icu_normalizer_data | 2.1.1 | registry+https://github.com/rust-lang/crates.io-index |
| icu_properties | 2.1.2 | registry+https://github.com/rust-lang/crates.io-index |
| icu_properties_data | 2.1.2 | registry+https://github.com/rust-lang/crates.io-index |
| icu_provider | 2.1.1 | registry+https://github.com/rust-lang/crates.io-index |
| id-arena | 2.3.0 | registry+https://github.com/rust-lang/crates.io-index |
| idna_adapter | 1.2.1 | registry+https://github.com/rust-lang/crates.io-index |
| indexmap | 2.13.0 | registry+https://github.com/rust-lang/crates.io-index |
| iri-string | 0.7.10 | registry+https://github.com/rust-lang/crates.io-index |
| is_terminal_polyfill | 1.70.2 | registry+https://github.com/rust-lang/crates.io-index |
| itoa | 1.0.17 | registry+https://github.com/rust-lang/crates.io-index |
| js-sys | 0.3.91 | registry+https://github.com/rust-lang/crates.io-index |
| leb128fmt | 0.1.0 | registry+https://github.com/rust-lang/crates.io-index |
| libc | 0.2.182 | registry+https://github.com/rust-lang/crates.io-index |
| libloading | 0.8.9 | registry+https://github.com/rust-lang/crates.io-index |
| litemap | 0.8.1 | registry+https://github.com/rust-lang/crates.io-index |
| log | 0.4.29 | registry+https://github.com/rust-lang/crates.io-index |
| matrixmultiply | 0.3.10 | registry+https://github.com/rust-lang/crates.io-index |
| memchr | 2.8.0 | registry+https://github.com/rust-lang/crates.io-index |
| mime_guess | 2.0.5 | registry+https://github.com/rust-lang/crates.io-index |
| mio | 1.1.1 | registry+https://github.com/rust-lang/crates.io-index |
| ndarray | 0.16.1 | registry+https://github.com/rust-lang/crates.io-index |
| num-complex | 0.4.6 | registry+https://github.com/rust-lang/crates.io-index |
| num-integer | 0.1.46 | registry+https://github.com/rust-lang/crates.io-index |
| once_cell | 1.21.3 | registry+https://github.com/rust-lang/crates.io-index |
| once_cell_polyfill | 1.70.2 | registry+https://github.com/rust-lang/crates.io-index |
| openssl | 0.10.76 | registry+https://github.com/rust-lang/crates.io-index |
| openssl-sys | 0.9.112 | registry+https://github.com/rust-lang/crates.io-index |
| ort | 2.0.0-rc.10 | registry+https://github.com/rust-lang/crates.io-index |
| ort-sys | 2.0.0-rc.10 | registry+https://github.com/rust-lang/crates.io-index |
| ovca-agent-core | 0.1.0 |  |
| ovca-aurora-server | 0.1.0 |  |
| ovca-brain-server | 0.1.0 |  |
| ovca-data | 0.1.0 |  |
| ovca-dispatch | 0.1.0 |  |
| ovca-dispatch-cli | 0.1.0 |  |
| ovca-divina-server | 0.1.0 |  |
| ovca-hope-server | 0.1.0 |  |
| ovca-kg-core | 0.1.0 |  |
| ovca-kg-server | 0.1.0 |  |
| ovca-obctl-omega | 0.1.0 |  |
| ovca-onnx | 0.1.0 |  |
| ovca-performance | 0.1.0 |  |
| ovca-registry-server | 0.1.0 |  |
| ovca-sati | 0.1.0 |  |
| ovca-sati-server | 0.1.0 |  |
| ovca-scheduler | 0.1.0 |  |
| ovca-skills-core | 0.1.0 |  |
| ovca-skills-runtime | 0.1.0 |  |
| ovca-web-server | 0.1.0 |  |
| ovca_anomaly | 0.1.0 |  |
| ovca_dedupe | 0.1.0 |  |
| ovca_graph_core | 0.1.0 |  |
| ovca_reporting | 0.1.0 |  |
| ovca_runtime | 0.1.0 |  |
| ovca_scheduler_core | 0.1.0 |  |
| pin-project | 1.1.11 | registry+https://github.com/rust-lang/crates.io-index |
| pin-project-internal | 1.1.11 | registry+https://github.com/rust-lang/crates.io-index |
| pin-utils | 0.1.0 | registry+https://github.com/rust-lang/crates.io-index |
| pkg-config | 0.3.32 | registry+https://github.com/rust-lang/crates.io-index |
| portable-atomic | 1.13.1 | registry+https://github.com/rust-lang/crates.io-index |
| portable-atomic-util | 0.2.5 | registry+https://github.com/rust-lang/crates.io-index |
| potential_utf | 0.1.4 | registry+https://github.com/rust-lang/crates.io-index |
| prettyplease | 0.2.37 | registry+https://github.com/rust-lang/crates.io-index |
| quote | 1.0.45 | registry+https://github.com/rust-lang/crates.io-index |
| r-efi | 5.3.0 | registry+https://github.com/rust-lang/crates.io-index |
| rawpointer | 0.2.1 | registry+https://github.com/rust-lang/crates.io-index |
| regex | 1.12.3 | registry+https://github.com/rust-lang/crates.io-index |
| regex-automata | 0.4.14 | registry+https://github.com/rust-lang/crates.io-index |
| regex-syntax | 0.8.10 | registry+https://github.com/rust-lang/crates.io-index |
| rustls | 0.23.37 | registry+https://github.com/rust-lang/crates.io-index |
| rustls-pki-types | 1.14.0 | registry+https://github.com/rust-lang/crates.io-index |
| rustls-webpki | 0.103.9 | registry+https://github.com/rust-lang/crates.io-index |
| rustversion | 1.0.22 | registry+https://github.com/rust-lang/crates.io-index |
| semver | 1.0.27 | registry+https://github.com/rust-lang/crates.io-index |
| serde_json | 1.0.149 | registry+https://github.com/rust-lang/crates.io-index |
| sha2 | 0.10.9 | registry+https://github.com/rust-lang/crates.io-index |
| shlex | 1.3.0 | registry+https://github.com/rust-lang/crates.io-index |
| smallvec | 1.15.1 | registry+https://github.com/rust-lang/crates.io-index |
| smallvec | 2.0.0-alpha.10 | registry+https://github.com/rust-lang/crates.io-index |
| socket2 | 0.6.3 | registry+https://github.com/rust-lang/crates.io-index |
| strsim | 0.11.1 | registry+https://github.com/rust-lang/crates.io-index |
| syn | 2.0.117 | registry+https://github.com/rust-lang/crates.io-index |
| tempfile | 3.26.0 | registry+https://github.com/rust-lang/crates.io-index |
| thread_local | 1.1.9 | registry+https://github.com/rust-lang/crates.io-index |
| tinystr | 0.8.2 | registry+https://github.com/rust-lang/crates.io-index |
| tokio | 1.50.0 | registry+https://github.com/rust-lang/crates.io-index |
| tokio-macros | 2.6.1 | registry+https://github.com/rust-lang/crates.io-index |
| tower-http | 0.6.8 | registry+https://github.com/rust-lang/crates.io-index |
| tracing-subscriber | 0.3.22 | registry+https://github.com/rust-lang/crates.io-index |
| typenum | 1.19.0 | registry+https://github.com/rust-lang/crates.io-index |
| unicase | 2.9.0 | registry+https://github.com/rust-lang/crates.io-index |
| unicode-xid | 0.2.6 | registry+https://github.com/rust-lang/crates.io-index |
| utf8parse | 0.2.2 | registry+https://github.com/rust-lang/crates.io-index |
| uuid | 1.22.0 | registry+https://github.com/rust-lang/crates.io-index |
| wasip2 | 1.0.2+wasi-0.2.9 | registry+https://github.com/rust-lang/crates.io-index |
| wasip3 | 0.4.0+wasi-0.3.0-rc-2026-01-06 | registry+https://github.com/rust-lang/crates.io-index |
| wasm-bindgen | 0.2.114 | registry+https://github.com/rust-lang/crates.io-index |
| wasm-bindgen-futures | 0.4.64 | registry+https://github.com/rust-lang/crates.io-index |
| wasm-bindgen-macro | 0.2.114 | registry+https://github.com/rust-lang/crates.io-index |
| wasm-bindgen-macro-support | 0.2.114 | registry+https://github.com/rust-lang/crates.io-index |
| wasm-bindgen-shared | 0.2.114 | registry+https://github.com/rust-lang/crates.io-index |
| wasm-encoder | 0.244.0 | registry+https://github.com/rust-lang/crates.io-index |
| wasm-metadata | 0.244.0 | registry+https://github.com/rust-lang/crates.io-index |
| wasmparser | 0.244.0 | registry+https://github.com/rust-lang/crates.io-index |
| web-sys | 0.3.91 | registry+https://github.com/rust-lang/crates.io-index |
| wit-bindgen | 0.51.0 | registry+https://github.com/rust-lang/crates.io-index |
| wit-bindgen-core | 0.51.0 | registry+https://github.com/rust-lang/crates.io-index |
| wit-bindgen-rust | 0.51.0 | registry+https://github.com/rust-lang/crates.io-index |
| wit-bindgen-rust-macro | 0.51.0 | registry+https://github.com/rust-lang/crates.io-index |
| wit-component | 0.244.0 | registry+https://github.com/rust-lang/crates.io-index |
| wit-parser | 0.244.0 | registry+https://github.com/rust-lang/crates.io-index |
| writeable | 0.6.2 | registry+https://github.com/rust-lang/crates.io-index |
| yoke | 0.8.1 | registry+https://github.com/rust-lang/crates.io-index |
| yoke-derive | 0.8.1 | registry+https://github.com/rust-lang/crates.io-index |
| zerocopy | 0.8.42 | registry+https://github.com/rust-lang/crates.io-index |
| zerocopy-derive | 0.8.42 | registry+https://github.com/rust-lang/crates.io-index |
| zerofrom | 0.1.6 | registry+https://github.com/rust-lang/crates.io-index |
| zerofrom-derive | 0.1.6 | registry+https://github.com/rust-lang/crates.io-index |
| zeroize | 1.8.2 | registry+https://github.com/rust-lang/crates.io-index |
| zerotrie | 0.2.3 | registry+https://github.com/rust-lang/crates.io-index |
| zerovec | 0.11.5 | registry+https://github.com/rust-lang/crates.io-index |
| zerovec-derive | 0.11.2 | registry+https://github.com/rust-lang/crates.io-index |
| zmij | 1.0.21 | registry+https://github.com/rust-lang/crates.io-index |

## Added package records

| Package | Version | Source |
|---|---:|---|
| anyhow | 1.0.103 | registry+https://github.com/rust-lang/crates.io-index |
| autocfg | 1.5.1 | registry+https://github.com/rust-lang/crates.io-index |
| bitflags | 2.13.1 | registry+https://github.com/rust-lang/crates.io-index |
| bumpalo | 3.20.3 | registry+https://github.com/rust-lang/crates.io-index |
| bytes | 1.12.1 | registry+https://github.com/rust-lang/crates.io-index |
| cc | 1.2.67 | registry+https://github.com/rust-lang/crates.io-index |
| chrono | 0.4.45 | registry+https://github.com/rust-lang/crates.io-index |
| displaydoc | 0.2.6 | registry+https://github.com/rust-lang/crates.io-index |
| fastrand | 2.4.1 | registry+https://github.com/rust-lang/crates.io-index |
| getrandom | 0.4.3 | registry+https://github.com/rust-lang/crates.io-index |
| h2 | 0.4.15 | registry+https://github.com/rust-lang/crates.io-index |
| hashbrown | 0.17.1 | registry+https://github.com/rust-lang/crates.io-index |
| http | 1.4.2 | registry+https://github.com/rust-lang/crates.io-index |
| http-body | 1.1.0 | registry+https://github.com/rust-lang/crates.io-index |
| http-body-util | 0.1.4 | registry+https://github.com/rust-lang/crates.io-index |
| hyper | 1.10.1 | registry+https://github.com/rust-lang/crates.io-index |
| hyper-rustls | 0.27.9 | registry+https://github.com/rust-lang/crates.io-index |
| icu_collections | 2.2.0 | registry+https://github.com/rust-lang/crates.io-index |
| icu_locale_core | 2.2.0 | registry+https://github.com/rust-lang/crates.io-index |
| icu_normalizer | 2.2.0 | registry+https://github.com/rust-lang/crates.io-index |
| icu_normalizer_data | 2.2.0 | registry+https://github.com/rust-lang/crates.io-index |
| icu_properties | 2.2.0 | registry+https://github.com/rust-lang/crates.io-index |
| icu_properties_data | 2.2.0 | registry+https://github.com/rust-lang/crates.io-index |
| icu_provider | 2.2.0 | registry+https://github.com/rust-lang/crates.io-index |
| idna_adapter | 1.2.2 | registry+https://github.com/rust-lang/crates.io-index |
| indexmap | 2.14.0 | registry+https://github.com/rust-lang/crates.io-index |
| itoa | 1.0.18 | registry+https://github.com/rust-lang/crates.io-index |
| js-sys | 0.3.103 | registry+https://github.com/rust-lang/crates.io-index |
| libc | 0.2.186 | registry+https://github.com/rust-lang/crates.io-index |
| litemap | 0.8.2 | registry+https://github.com/rust-lang/crates.io-index |
| log | 0.4.33 | registry+https://github.com/rust-lang/crates.io-index |
| memchr | 2.8.3 | registry+https://github.com/rust-lang/crates.io-index |
| mio | 1.2.2 | registry+https://github.com/rust-lang/crates.io-index |
| once_cell | 1.21.4 | registry+https://github.com/rust-lang/crates.io-index |
| openssl | 0.10.81 | registry+https://github.com/rust-lang/crates.io-index |
| openssl-sys | 0.9.117 | registry+https://github.com/rust-lang/crates.io-index |
| pin-project | 1.1.13 | registry+https://github.com/rust-lang/crates.io-index |
| pin-project-internal | 1.1.13 | registry+https://github.com/rust-lang/crates.io-index |
| pkg-config | 0.3.33 | registry+https://github.com/rust-lang/crates.io-index |
| potential_utf | 0.1.5 | registry+https://github.com/rust-lang/crates.io-index |
| quote | 1.0.46 | registry+https://github.com/rust-lang/crates.io-index |
| r-efi | 6.0.0 | registry+https://github.com/rust-lang/crates.io-index |
| regex | 1.13.1 | registry+https://github.com/rust-lang/crates.io-index |
| regex-automata | 0.4.16 | registry+https://github.com/rust-lang/crates.io-index |
| regex-syntax | 0.8.11 | registry+https://github.com/rust-lang/crates.io-index |
| rustls | 0.23.42 | registry+https://github.com/rust-lang/crates.io-index |
| rustls-pki-types | 1.15.0 | registry+https://github.com/rust-lang/crates.io-index |
| rustls-webpki | 0.103.13 | registry+https://github.com/rust-lang/crates.io-index |
| rustversion | 1.0.23 | registry+https://github.com/rust-lang/crates.io-index |
| serde_json | 1.0.150 | registry+https://github.com/rust-lang/crates.io-index |
| shlex | 2.0.1 | registry+https://github.com/rust-lang/crates.io-index |
| smallvec | 1.15.2 | registry+https://github.com/rust-lang/crates.io-index |
| socket2 | 0.6.5 | registry+https://github.com/rust-lang/crates.io-index |
| syn | 2.0.119 | registry+https://github.com/rust-lang/crates.io-index |
| tempfile | 3.27.0 | registry+https://github.com/rust-lang/crates.io-index |
| thread_local | 1.1.10 | registry+https://github.com/rust-lang/crates.io-index |
| tinystr | 0.8.3 | registry+https://github.com/rust-lang/crates.io-index |
| tokio | 1.52.3 | registry+https://github.com/rust-lang/crates.io-index |
| tokio-macros | 2.7.0 | registry+https://github.com/rust-lang/crates.io-index |
| tower-http | 0.6.11 | registry+https://github.com/rust-lang/crates.io-index |
| tracing-subscriber | 0.3.23 | registry+https://github.com/rust-lang/crates.io-index |
| uuid | 1.24.0 | registry+https://github.com/rust-lang/crates.io-index |
| wasm-bindgen | 0.2.126 | registry+https://github.com/rust-lang/crates.io-index |
| wasm-bindgen-futures | 0.4.76 | registry+https://github.com/rust-lang/crates.io-index |
| wasm-bindgen-macro | 0.2.126 | registry+https://github.com/rust-lang/crates.io-index |
| wasm-bindgen-macro-support | 0.2.126 | registry+https://github.com/rust-lang/crates.io-index |
| wasm-bindgen-shared | 0.2.126 | registry+https://github.com/rust-lang/crates.io-index |
| web-sys | 0.3.103 | registry+https://github.com/rust-lang/crates.io-index |
| writeable | 0.6.3 | registry+https://github.com/rust-lang/crates.io-index |
| yoke | 0.8.3 | registry+https://github.com/rust-lang/crates.io-index |
| yoke-derive | 0.8.2 | registry+https://github.com/rust-lang/crates.io-index |
| zerocopy | 0.8.54 | registry+https://github.com/rust-lang/crates.io-index |
| zerocopy-derive | 0.8.54 | registry+https://github.com/rust-lang/crates.io-index |
| zerofrom | 0.1.8 | registry+https://github.com/rust-lang/crates.io-index |
| zerofrom-derive | 0.1.7 | registry+https://github.com/rust-lang/crates.io-index |
| zeroize | 1.9.0 | registry+https://github.com/rust-lang/crates.io-index |
| zerotrie | 0.2.4 | registry+https://github.com/rust-lang/crates.io-index |
| zerovec | 0.11.6 | registry+https://github.com/rust-lang/crates.io-index |
| zerovec-derive | 0.11.3 | registry+https://github.com/rust-lang/crates.io-index |
| zmij | 1.0.23 | registry+https://github.com/rust-lang/crates.io-index |
