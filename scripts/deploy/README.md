# Fief production releases

Every successful main build emits its exact platform image digest. The operator
host follows main and deploys that receipt automatically; CI waits for the
matching deployment status. Existing environment and secret references are
preserved. Verification checks source revision, actual container image ID,
readiness, and absence of old pods. Older workflow runs cannot roll back a newer
completed release.

Install the timer on the existing operator host:

```sh
install -Dm755 scripts/deploy/fief-release-launch.sh ~/.local/lib/opensensor-hosting/fief-release-launch.sh
install -Dm644 scripts/deploy/opensensor-fief-release.service ~/.config/systemd/user/opensensor-fief-release.service
install -Dm644 scripts/deploy/opensensor-fief-release.timer ~/.config/systemd/user/opensensor-fief-release.timer
systemctl --user daemon-reload
systemctl --user enable --now opensensor-fief-release.timer
```

Existing host GitHub and Kubernetes credentials are used. Inspect failures with
`journalctl --user -u opensensor-fief-release.service`; retries are automatic.
The companion storefront change stops GrowMax deployments from reapplying a
historical Fief image. Merge this Fief change first so its release helper is
available to the storefront's manual recovery workflow.
