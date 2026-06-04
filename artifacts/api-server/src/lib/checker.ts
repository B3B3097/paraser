import net from "net";
import tls from "tls";
import https from "https";
import http from "http";

export type CheckLevel = "tcp" | "tls" | "http";

export interface CheckResult {
  tcpStatus: "ok" | "fail" | null;
  tlsStatus: "ok" | "fail" | null;
  httpStatus: "ok" | "fail" | null;
  latencyMs: number | null;
}

function checkTcp(host: string, port: number, timeoutMs: number): Promise<{ ok: boolean; latencyMs: number }> {
  return new Promise((resolve) => {
    const start = Date.now();
    const socket = new net.Socket();
    let done = false;

    const finish = (ok: boolean) => {
      if (done) return;
      done = true;
      socket.destroy();
      resolve({ ok, latencyMs: Date.now() - start });
    };

    socket.setTimeout(timeoutMs);
    socket.connect(port, host, () => finish(true));
    socket.on("error", () => finish(false));
    socket.on("timeout", () => finish(false));
  });
}

function checkTls(host: string, port: number, sni: string | null, timeoutMs: number): Promise<{ ok: boolean; latencyMs: number }> {
  return new Promise((resolve) => {
    const start = Date.now();
    let done = false;

    const finish = (ok: boolean) => {
      if (done) return;
      done = true;
      try { socket.destroy(); } catch { /* ignore */ }
      resolve({ ok, latencyMs: Date.now() - start });
    };

    const socket = tls.connect(
      {
        host,
        port,
        servername: sni || host,
        rejectUnauthorized: false,
        timeout: timeoutMs,
      },
      () => finish(true),
    );

    socket.on("error", () => finish(false));
    socket.on("timeout", () => finish(false));

    setTimeout(() => finish(false), timeoutMs + 500);
  });
}

function checkHttp(host: string, port: number, sni: string | null, path: string | null, timeoutMs: number): Promise<{ ok: boolean; latencyMs: number }> {
  return new Promise((resolve) => {
    const start = Date.now();
    let done = false;

    const finish = (ok: boolean) => {
      if (done) return;
      done = true;
      resolve({ ok, latencyMs: Date.now() - start });
    };

    const urlPath = path || "/";
    const isHttps = port === 443 || port === 8443;
    const reqModule = isHttps ? https : http;

    try {
      const req = reqModule.request(
        {
          hostname: host,
          port,
          path: urlPath,
          method: "GET",
          timeout: timeoutMs,
          rejectUnauthorized: false,
          servername: sni || host,
          headers: {
            Host: sni || host,
            "User-Agent": "Mozilla/5.0",
          },
        },
        (res) => {
          res.resume();
          finish(res.statusCode !== undefined && res.statusCode < 600);
        },
      );

      req.on("error", () => finish(false));
      req.on("timeout", () => {
        req.destroy();
        finish(false);
      });
      req.end();

      setTimeout(() => {
        req.destroy();
        finish(false);
      }, timeoutMs + 1000);
    } catch {
      finish(false);
    }
  });
}

export async function checkConfig(
  host: string,
  port: number,
  sni: string | null,
  path: string | null,
  level: CheckLevel,
  timeoutMs = 5000,
): Promise<CheckResult> {
  const result: CheckResult = {
    tcpStatus: null,
    tlsStatus: null,
    httpStatus: null,
    latencyMs: null,
  };

  const tcpResult = await checkTcp(host, port, timeoutMs);
  result.tcpStatus = tcpResult.ok ? "ok" : "fail";
  result.latencyMs = tcpResult.latencyMs;

  if (!tcpResult.ok || level === "tcp") {
    return result;
  }

  const tlsResult = await checkTls(host, port, sni, timeoutMs);
  result.tlsStatus = tlsResult.ok ? "ok" : "fail";
  if (tlsResult.ok) result.latencyMs = tlsResult.latencyMs;

  if (!tlsResult.ok || level === "tls") {
    return result;
  }

  const httpResult = await checkHttp(host, port, sni, path, timeoutMs);
  result.httpStatus = httpResult.ok ? "ok" : "fail";
  if (httpResult.ok) result.latencyMs = httpResult.latencyMs;

  return result;
}

export async function checkBatch(
  configs: Array<{ id: number; host: string; port: number; sni: string | null; path: string | null }>,
  level: CheckLevel,
  concurrency: number,
  timeoutMs: number,
  onResult: (id: number, result: CheckResult) => void,
): Promise<void> {
  const queue = [...configs];
  let active = 0;

  await new Promise<void>((resolve) => {
    const next = () => {
      if (queue.length === 0 && active === 0) {
        resolve();
        return;
      }

      while (active < concurrency && queue.length > 0) {
        const item = queue.shift()!;
        active++;

        checkConfig(item.host, item.port, item.sni, item.path, level, timeoutMs)
          .then((result) => {
            onResult(item.id, result);
          })
          .catch(() => {
            onResult(item.id, { tcpStatus: "fail", tlsStatus: null, httpStatus: null, latencyMs: null });
          })
          .finally(() => {
            active--;
            next();
          });
      }
    };

    next();
  });
}
