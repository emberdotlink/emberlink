# GitHub Setup and Auth

The current GitHub story is **App-first**.

That means:

- the preferred lane is a locally registered GitHub App credential triple
- the operator-friendly wrapper is `ember github setup`
- `github-pat` exists only as a degraded fallback

## The most important truth

The public Emberlink GitHub App is a real public reference surface, but it is
**not** a self-sufficient local setup path by itself.

Why:

- the local daemon can mint GitHub installation tokens only from App
  credentials it can reach locally
- installing the public App alone does not give the daemon the private key it
  needs to mint those tokens

So for v0.3.x, the real brokered GitHub path is still:

```bash
ember github setup
```

## What `ember github setup` asks for

The friendly setup wrapper expects these inputs:

- private key PEM
- App ID
- installation URL or installation ID
- App slug

That is the current truthful local App lane.

## What the public App surface is for

The public App manifest and install URL are still useful:

- they document the permission floor
- they provide the public install target
- they let operators verify the intended App identity

But they are reference surfaces, not a complete turnkey setup story for the
local daemon today.

## How to confirm GitHub posture

Use:

```bash
ember github status --json
ember github status
```

The status output should make it clear whether you are on:

- the App lane
- the degraded PAT lane
- or an unconfigured posture

## PAT truth

`github-pat` is not equal to the App lane.

PAT fallback is:

- explicit
- degraded
- useful for compatibility and recovery

It does **not** have the same properties as the App lane’s short-lived
installation-token model.

If you intentionally choose degraded fallback, do it honestly and treat it as
recovery posture rather than the headline setup story.

## First commands to try

```bash
ember github status --json
ember github setup
ember doctor
```

If GitHub is the only missing part of your install, those commands are the
right first repair path.
