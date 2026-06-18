Static fixture for `cosign_dual_witness_real_fixture_integration`.

`manifest.cosign-bundle.json` is a no-Rekor negative fixture generated with
the release-workflow-pinned `cosign` v2.5.0:

```bash
COSIGN_PASSWORD=test cosign generate-key-pair --output-key-prefix test-publisher-cosign
COSIGN_PASSWORD=test cosign sign-blob --yes \
  --key test-publisher-cosign.key \
  --tlog-upload=false \
  --new-bundle-format \
  --bundle manifest.cosign-bundle.json \
  --output-signature manifest.cosign.sig \
  manifest.json
openssl genpkey -algorithm ED25519 -out test-identity-root.key
openssl pkeyutl -sign -inkey test-identity-root.key -rawin \
  -in manifest.json -out manifest.identity-root.sig
```

The private keys are test-only generation inputs and are intentionally not
committed. This fixture does not claim production Rekor coverage and must be
rejected by `verify_manifest_dual_witness`.

`real-rekor-artifact.txt` and `real-rekor.cosign-bundle.json` are copied from
the upstream sigstore-rs `SignedArtifactBundle` example:

```bash
echo something > artifact.txt
cosign sign-blob --bundle=artifact.bundle artifact.txt
```

The bundle includes a public Rekor signed entry timestamp over the hashedrekord
payload for `sha256(real-rekor-artifact.txt)`.
