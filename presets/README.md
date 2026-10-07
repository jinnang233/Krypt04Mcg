# Configuration presets

These complete configuration files work with both Fabric and NeoForge. Settings
other than the algorithms match the defaults in Krypt04Mcg 0.26.1.

| Preset | Long-term KEM | Ephemeral KEM | Signature | AEAD |
| --- | --- | --- | --- | --- |
| [Default](default.json) | `ML-KEM-768+X25519` | `ML-KEM-768+X25519` | `MLDSA65-Ed25519-SHA512` | `AES-256-GCM` |
| [Compact](compact.json) | `CMCE/mceliece460896` | `ML-KEM-512` | `UOV-IS` | `AES-256-GCM` |
| [CMCE + Falcon](cmce-falcon.json) | `CMCE/mceliece8192128f` | `ML-KEM-768+X25519` | `Falcon-1024` | `AES-256-GCM` |
| [SLH-DSA](slh-dsa.json) | `ML-KEM-768+X25519` | `ML-KEM-768+X25519` | `SLH-DSA-SHA2-192S` | `AES-256-GCM` |
| [BC hybrid, category 5](bc-hybrid-category-5.json) | `ML-KEM-1024+X448` | `ML-KEM-1024+X448` | `MLDSA87-Ed448-SHAKE256` | `AES-256-GCM` |

`default.json` reproduces the current defaults, including disabled file sharing,
data API and conversation history. The SLH-DSA preset changes only the signature
algorithm. Its SHA2-192S parameters have NIST security category 3; the `S` variant
favors smaller signatures over signing speed. Each signature is 16,224 bytes, so
signed chat messages require substantially more fragments than the default.
See [FIPS 205, Table 2](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf).

The compact preset minimizes the combined signature and KEM ciphertext size for
signed direct messages among the currently supported selections: CMCE
`mceliece460896` produces a 156-byte encapsulation and `UOV-IS` a 96-byte
signature, totaling 252 bytes. The CMCE `f` variant and the UOV-IS compressed-key
variants tie on these sizes. AES-256-GCM adds a 16-byte authentication tag to the
encoded (optionally compressed) plaintext; the 12-byte nonce, packet headers and
transport encoding are additional overhead. These sizes were checked with BC
1.86; see also the [UOV parameter table](https://github.com/pqov/pqov#parameters)
and [Classic McEliece ciphertext encoding](https://classic.mceliece.org/mceliece-sage-20221023/byterepr.sage.html).

Compact optimizes message size rather than key size: the raw CMCE and UOV public
keys are 524,160 and 412,160 bytes respectively. Exported key files are practical
for exchanging these keys. The ephemeral KEM uses `ML-KEM-512`, whose 768-byte
encapsulation is the smallest supported choice that fits the session handshake;
all supported CMCE public keys exceed its 64 KiB plaintext limit. UOV-IS and
ML-KEM-512 target NIST security category 1, and UOV is an experimental,
non-standardized signature selection. This preset uses standalone PQ algorithms
without the defaults' classical hybrid components.

The CMCE preset uses BC's CMCE and Falcon implementations. Its long-term CMCE
public key is much larger than an ML-KEM public key; exchanging exported public
key files through a trusted side channel is practical for this preset. The
ephemeral KEM stays at the default because embedding a CMCE public key in a
session handshake would exceed the protocol's 64 KiB plaintext limit.

The category 5 preset uses the highest NIST security category for its standardized
post-quantum components: ML-KEM-1024 and ML-DSA-87. See
[FIPS 203](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf) and
[FIPS 204](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf).
Both KEM selections call BC's native `MLKEM1024-X448-SHA3-256` implementation,
and the signature calls BC's native `MLDSA87-Ed448-SHAKE256` implementation.
Neither selection uses the mod's custom hybrid combiner. The component algorithms
are standardized; the hybrid construction and encoding are BC's composite suites.

## Applying a preset

1. Install Cloth Config for your loader. Both loaders use it to load saved settings;
   without it, Krypt04Mcg uses its built-in defaults.
2. Close Minecraft and back up the instance's `config/krypt04mcg.json`, if present.
3. Copy the chosen JSON file to that location, naming it `krypt04mcg.json`.
   This replaces the whole configuration. To keep your other preferences, copy
   only `kemAlgorithm`, `ephemeralKemAlgorithm`, `signatureAlgorithm` and
   `aeadAlgorithm` into your existing file instead.
4. Start Minecraft. If you already have local keys and changed the long-term KEM
   or signature, run `/k04m key regenerate` and then the confirmation command it
   prints. Export and redistribute your new public keys; peers must deliberately
   replace their old imported keys and verify the new fingerprints. See the
   [key regeneration instructions](../README.md#commands).

The signature setting applies to signed messages and session exchanges. Use
`/k04m stell` for signed direct messages. Existing key files are separate from the
configuration file; copying a preset does not regenerate them.
