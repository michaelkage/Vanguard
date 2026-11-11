/**
 * Coalesces overlapping permission prompts without caching their result.
 *
 * A successful permission grant is not permanent: the user can revoke it in
 * system settings. Each later operation therefore performs a fresh check once
 * the previous in-flight request has settled.
 */
export class PermissionRequestCoordinator {
  private inFlight: Promise<void> | undefined;

  run(request: () => Promise<void>): Promise<void> {
    if (this.inFlight) return this.inFlight;

    const operation = Promise.resolve().then(request);
    this.inFlight = operation;

    const clear = () => {
      if (this.inFlight === operation) this.inFlight = undefined;
    };
    void operation.then(clear, clear);

    return operation;
  }
}
