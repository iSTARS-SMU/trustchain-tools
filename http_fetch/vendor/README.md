# vendor/ — bundled trustchain packages

**Do not edit by hand.** Synced from the trustchain monorepo at push time
by `trustchain/scripts/push-tools.sh`. This keeps the tool buildable
without access to the private trustchain source.

What's here:
  * `vendor/contracts` — trustchain-contracts source (DTOs / events / scope matcher / ...)

Installed into the Docker image via `Dockerfile`:

    COPY vendor/contracts /opt/contracts
    RUN pip install --no-cache-dir /opt/contracts

Upgrading: re-run `push-tools.sh` from the trustchain monorepo. A new bundle
becomes a new commit here.
