import { describe, expect, it, vi } from "vitest";
import { PermissionRequestCoordinator } from "./permission-request-coordinator";

function deferred<T>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((complete, fail) => {
    resolve = complete;
    reject = fail;
  });
  return { promise, resolve, reject };
}

describe("PermissionRequestCoordinator", () => {
  it("shares one in-flight permission request across concurrent radio starts", async () => {
    const coordinator = new PermissionRequestCoordinator();
    const pending = deferred<void>();
    const request = vi.fn(() => pending.promise);

    const advertising = coordinator.run(request);
    const discovery = coordinator.run(request);

    expect(request).not.toHaveBeenCalled();
    await Promise.resolve();
    expect(request).toHaveBeenCalledOnce();

    pending.resolve();
    await Promise.all([advertising, discovery]);
  });

  it("does not cache permission grants after the request settles", async () => {
    const coordinator = new PermissionRequestCoordinator();
    const request = vi.fn().mockResolvedValue(undefined);

    await coordinator.run(request);
    await coordinator.run(request);

    expect(request).toHaveBeenCalledTimes(2);
  });

  it("clears rejected requests and permits a later retry", async () => {
    const coordinator = new PermissionRequestCoordinator();
    const request = vi.fn()
      .mockRejectedValueOnce(new Error("Permission service unavailable"))
      .mockResolvedValueOnce(undefined);

    await expect(coordinator.run(request)).rejects.toThrow(
      "Permission service unavailable"
    );
    await coordinator.run(request);

    expect(request).toHaveBeenCalledTimes(2);
  });

  it("shares a rejection with every concurrent caller", async () => {
    const coordinator = new PermissionRequestCoordinator();
    const pending = deferred<void>();
    const request = vi.fn(() => pending.promise);

    const first = coordinator.run(request);
    const second = coordinator.run(request);
    const firstResult = expect(first).rejects.toThrow("Permission denied");
    const secondResult = expect(second).rejects.toThrow("Permission denied");

    await Promise.resolve();
    expect(request).toHaveBeenCalledOnce();
    pending.reject(new Error("Permission denied"));

    await Promise.all([firstResult, secondResult]);
  });
});
