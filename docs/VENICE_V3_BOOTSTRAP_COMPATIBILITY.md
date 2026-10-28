# Venice V3 bootstrap compatibility contract

The V3 release chain is deliberately split into three executables:

1. `OrionActivate.exe` is the signed device-bound broker. It verifies the
   signed customer manifest, proves possession of the device key, obtains a
   short-lived V3 grant, decrypts the device-bound envelope in memory, and owns
   the packed-child process lifetime.
2. `OrionNative.exe` is `LetheShardBootstrap.exe`. It accepts the 40-byte
   `VSG3` frame only from the broker's inherited anonymous stdin pipe, forwards
   only that closed handle to the packed payload, and never reads a shard from
   an environment variable, command line, cache, or network request.
3. `OrionNative.packed.exe` consumes exactly one `VSG3` frame, requires EOF,
   and zeroes its private copy after deriving the payload key.

## Broker binding

The bootstrap is configured with the exact public SHA-256 of the release's
`OrionActivate.exe`. The compiled bootstrap contains one public
`ORION_ACTIVATE_SHA256:<digest>` marker. Direct startup may delegate only to a
sibling broker whose bytes match that digest; it cannot launch the packed child
or reconstruct a grant itself.

The digest is release-integrity metadata, not a credential. Device proofs,
session state, shard publication, KMS access, and the grant private key remain
outside the bootstrap.

## Qualification requirements

Production assembly accepts this compatibility layer only when all of the
following are true:

- the Lethe commit and committed V3 profile are clean and hash-pinned;
- a fresh stub candidate records its complete native source input inventory;
- CTest proves the compatibility bootstrap's hashing and broker-marker logic;
- the VSG3 native tests reject absent, malformed, replay-shaped, and trailing
  frames before exercising the exact valid-frame path; and
- the final bootstrap and broker are separately attested by exact SHA-256
  before either is placed in the signed customer manifest.

This contract is a compatibility bridge, not an OS-level code-signing root.
The broker's signed manifest, device proof, backend entitlement checks, and
server revocation remain authoritative.
