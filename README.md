# Program AI Desktop binary verification

Signed test assets and a small public binary-verification driver only. This is
not the customer download repository or production update feed. It contains no
private application source, account credentials, or Apple/provider keys.

## Cost and execution boundary

The owner approved one-off verification on 2026-10-29. The manually dispatched
workflow uses only GitHub's **standard public-repository** `macos-15` (Apple
silicon) and `macos-15-intel` runners. It does not build the application, run on
push/a schedule, enable private-repository Actions, change a spending setting,
use an Actions cache, or upload Actions artifacts. Results are bounded job logs
and job summaries. Larger/self-hosted/private runners are not configured.

The driver must refuse an owner's Mac, translated architecture, private repo,
non-owner dispatch, or unexpected source/ref. Never spoof runner variables.
Actual artifact hashes and signatures are checked before execution. Missing
native browser/diagnostic capability is **unverified**, not a product pass.
Fuses, TCC, Gatekeeper, quarantine, and signature checks must never be weakened.

The reviewed baseline and candidate versions include paired conditional `msgpackr-extract` platform
resources. The verifier checks their exact paths, package metadata, declared
CPU, signed binary hashes, and loader hashes; the loader selects the current
platform/architecture. This narrow resource rule does not admit other
wrong-architecture code. The main executable and every other native component
must match the requested architecture, and actual native launch remains a
separate required check. The original failed inventory run is not a native-app
pass and remains in the public test history.

## Candidate evidence

`ci/candidate.json` pins exact already-signed assets, source metadata, hashes,
and byte sizes. Local build observations are not GitHub build attestations.
Test assets and a successful trust check alone do not establish all production
acceptance, account billing, voice, or native installation/update behavior.

The current candidate is 1.0.10 with signed 1.0.8 as the update baseline. A
download-ready state is not native signature acceptance: the signature-negative
case exercises the unchanged Install preflight, requires an actual Squirrel
signature-domain rejection with the original app/data still usable, then
restarts normally before a genuine signed recovery update. Public receipts
continue to exclude paid coding, production-account, editor-draft and queue
claims. The post-update shell fixture checks only the packaged command boundary
inside its disposable project.
