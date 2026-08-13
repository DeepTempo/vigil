import type { PoolConfig } from "pg";

// DATABASE_URL wins so CI and the integration test keep passing a DSN, but a
// deployed process has no DSN to pass: the chart ships discrete POSTGRES_* vars
// because Kubernetes `$(VAR)` substitution does no URL-encoding, so a password
// containing @ or / would render a malformed one (infra/helm/vigil/templates/
// _env.tpl). pg takes the parts, so nothing needs encoding either way.
//
// Here rather than in worker.ts because both entry points open a pool: the worker
// drains the queue and serve answers the HTTP surface, and they are separate
// Deployments since #635.
export function poolConfig(): PoolConfig {
  const url = process.env["DATABASE_URL"];
  if (url !== undefined && url !== "") return { connectionString: url };

  const host = process.env["POSTGRES_HOST"];
  if (host === undefined || host === "") {
    throw new Error("set DATABASE_URL, or POSTGRES_HOST and the other POSTGRES_* vars");
  }
  return {
    host,
    port: Number(process.env["POSTGRES_PORT"] ?? 5432),
    database: process.env["POSTGRES_DB"],
    user: process.env["POSTGRES_USER"],
    password: process.env["POSTGRES_PASSWORD"],
  };
}

// What BullMQ needs of a Redis, which is the parts and not a URL.
export interface RedisConfig {
  host: string;
  port: number;
  db: number;
  password?: string;
}

// The parts win here, which is the other way round from poolConfig above, and the
// difference is the chart rather than a preference. `vigil.env` hands every pod a
// REDIS_URL because the Python deployables read one, and under Bitnami auth that
// URL is `redis://:$(REDIS_PASSWORD)@host:6379/0` -- substituted by the kubelet,
// which does no URL-encoding. A password holding @ / : or # therefore renders a
// URL that `new URL()` misparses or rejects outright, and the parts beside it are
// the only correct reading. So: parts when the deployment named them, URL when it
// only had one to give (an external Redis, CI, a dev box).
//
// The URL branch decodes the password: `new URL()` leaves it percent-encoded, so a
// correctly-escaped DSN would otherwise authenticate with the escapes still in it.
export function redisConfig(): RedisConfig {
  const host = process.env["REDIS_HOST"];
  if (host !== undefined && host !== "") {
    const password = process.env["REDIS_PASSWORD"];
    return {
      host,
      port: Number(process.env["REDIS_PORT"] ?? 6379),
      db: Number(process.env["REDIS_DB"] ?? 0),
      ...(password === undefined || password === "" ? {} : { password }),
    };
  }

  const url = new URL(process.env["REDIS_URL"] ?? "redis://localhost:6379/0");
  return {
    host: url.hostname,
    port: Number(url.port || 6379),
    db: Number(url.pathname.slice(1) || 0),
    ...(url.password === "" ? {} : { password: decodeURIComponent(url.password) }),
  };
}
