# Signed agent releases

Closes the last fleet-wide code-delivery vector in the compromised-API /
botnet threat model: previously a self-updating agent trusted only a
sha256 fetched from the **same** GitHub release, so anyone able to publish
a release could replace both the binary and its checksum. Now every release
artifact is minisign-signed with an **offline** key (never in CI, same
model as the registry manifest key), and the update path verifies the
signature using a public key **embedded in the already-installed, trusted
agent binary** — the attacker would additionally need the offline secret.

## Two anchored verification points

Both are driven by trusted, already-on-device code, not by freshly
downloaded scripts:

1. **`obacht-self-update` wrapper** (fixed-content, pinned by sudoers) →
   downloads `install.sh` + `install.sh.minisig`, verifies it with the
   installed `obacht-agent verify-release` **before executing it**. Stops a
   malicious install.sh from simply skipping the tarball check.
2. **`install.sh --self-update`** → downloads the tarball + `.minisig`,
   verifies it with the installed (old) `obacht-agent verify-release`
   **before swapping** the binary.

`obacht-agent verify-release --file F --sig F.minisig` exit codes are the
contract:

| exit | meaning | installer action |
|---|---|---|
| 0 | verified | proceed |
| 1 | signature **rejected** | **abort** (tamper signal) |
| 2 | cannot verify (no embedded keys yet / bad usage) | warn + fall back to sha256+TLS |

Fresh `curl \| bash` installs have no prior trusted binary to anchor in, so
they rest on TLS + sha256 (TOFU) exactly as before — signing changes only
the **self-update** path.

## Staged rollout (fail-closed, no fleet breakage)

- `internal/selfupdate/EmbeddedReleaseKeys` ships **empty** → `verify-release`
  returns exit 2 → installer warns and continues on sha256. Nothing breaks.
- Generate the offline key, embed the pubkey, ship an agent release: from
  then on releases carry `.minisig` and updates are verified. Devices still
  on the old agent skip (exit 2) until they update once.
- Once the fleet reports the signing-capable version, make it mandatory
  (drop the exit-2 fallback to a hard error in a later install.sh).

## Key ceremony (release engineer, one-time)

```bash
# 1. Generate the OFFLINE key. Back the .key up off-machine immediately.
minisign -G \
  -s ~/.config/obacht/obacht-agent-release-1.key \
  -p ~/.config/obacht/obacht-agent-release-1.pub

# 2. Paste the .pub (both lines) into internal/selfupdate/embedded.go
#    → EmbeddedReleaseKeys, set Label to the key id. Commit + release an
#    agent version (this build can then verify FUTURE signed releases).

# 3. From the NEXT release on, after CI publishes, sign locally:
MINISIGN_PASSWORD='…' ./scripts/sign-release.sh v0.4.1
#    → downloads every *.tar.gz + install.sh, re-checks sha256,
#      minisign-signs, re-verifies against the pubkey, uploads *.minisig.
```

The secret key **never** goes into GitHub Actions — that is the entire
point (a CI compromise must not be able to sign a release).

Rotation: append the new key to `EmbeddedReleaseKeys`, ship the agent,
sign releases with both keys for one cycle, then remove the old entry.
Operators can also drop extra `.pub` files under `/etc/obacht/release-trust.d/`.
