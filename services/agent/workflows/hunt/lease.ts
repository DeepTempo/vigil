import { randomBytes } from "node:crypto";
import { readFileSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { hostname } from "node:os";
import { actorName } from "./actor.js";

export const DEFAULT_LEASE_TTL_MS = 600_000;

export class LeaseHeld extends Error {}

interface LeaseFile {
  nonce: string;
  owner: string;
  pid: number;
  acquired_at: string;
  expires_at: string;
}

function leasePath(ledgerPath: string): string {
  return `${ledgerPath}.lease`;
}

function read(path: string): LeaseFile | null {
  try {
    return JSON.parse(readFileSync(path, "utf8")) as LeaseFile;
  } catch {
    return null;
  }
}

// Only one process may advance a hunt, and expiry at acquire time is what
// reclaims a lease from a crashed one — there is no watchdog to run.
export class Lease {
  private constructor(
    readonly ledgerPath: string,
    private readonly nonce: string,
    private readonly ttlMs: number,
  ) {}

  static acquire(ledgerPath: string, ttlMs = DEFAULT_LEASE_TTL_MS): Lease {
    const path = leasePath(ledgerPath);
    const nonce = randomBytes(8).toString("hex");
    const body = (): string =>
      JSON.stringify({
        nonce,
        owner: `${actorName()}@${hostname()}`,
        pid: process.pid,
        acquired_at: new Date().toISOString(),
        expires_at: new Date(Date.now() + ttlMs).toISOString(),
      } satisfies LeaseFile);

    try {
      writeFileSync(path, body(), { flag: "wx" });
      return new Lease(ledgerPath, nonce, ttlMs);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
    }

    const held = read(path);
    if (held !== null && Date.parse(held.expires_at) > Date.now()) {
      throw new LeaseHeld(`${ledgerPath} is held by ${held.owner} (pid ${held.pid}) until ${held.expires_at}`);
    }

    // Rename is atomic, so two stealers both land a file; only the one whose
    // nonce survives the read-back owns the lease.
    const staging = `${path}.${nonce}`;
    writeFileSync(staging, body());
    renameSync(staging, path);
    if (read(path)?.nonce !== nonce) {
      throw new LeaseHeld(`${ledgerPath} was reclaimed by another process`);
    }
    return new Lease(ledgerPath, nonce, ttlMs);
  }

  renew(): void {
    const path = leasePath(this.ledgerPath);
    const held = read(path);
    if (held?.nonce !== this.nonce) throw new LeaseHeld(`lost the lease on ${this.ledgerPath}`);
    writeFileSync(path, JSON.stringify({ ...held, expires_at: new Date(Date.now() + this.ttlMs).toISOString() }));
  }

  release(): void {
    const path = leasePath(this.ledgerPath);
    if (read(path)?.nonce !== this.nonce) return;
    try {
      unlinkSync(path);
    } catch {
      // Already gone: a reclaim beat us to it, which is the same end state.
    }
  }
}
