import { userInfo } from "node:os";

// Who this process is, for attribution. Its own module because both the inbox and
// the lease need it and neither is about the other: a directive records who
// steered a run, a lease records who holds it.
export function actorName(): string {
  return process.env["VIGIL_ACTOR"] || userInfo().username;
}
