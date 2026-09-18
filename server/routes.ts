import { Router, type Request, type Response } from "express";
import { z } from "zod";
import path from "path";
import fs from "fs";
import { exec } from "child_process";
import { dbStore, type ConfigRecord } from "./db";
import { extractVlessFromText, tryDecodeBase64 } from "./vless-parser";
import { checkBatch, type CheckLevel, type CheckResult } from "./checker";
import { getHostFlag, buildConfigName, rebuildUriWithName } from "./geo";

export const apiRouter = Router();

// Checker Job State
interface CheckerJobState {
  running: boolean;
  level: CheckLevel | null;
  total: number;
  checked: number;
  working: number;
  failed: number;
  startedAt: string | null;
}

const checkerJobState: CheckerJobState = {
  running: false,
  level: null,
  total: 0,
  checked: 0,
  working: 0,
  failed: 0,
  startedAt: null,
};

// Health
apiRouter.get("/health", (_req: Request, res: Response) => {
  res.json({ status: "ok", timestamp: new Date().toISOString() });
});

// Configs Stats
apiRouter.get("/configs/stats", (_req: Request, res: Response) => {
  res.json(dbStore.getConfigStats());
});

// List Configs
apiRouter.get("/configs", (req: Request, res: Response) => {
  const status = req.query.status as string | undefined;
  const checkLevel = req.query.checkLevel as string | undefined;
  const configs = dbStore.getConfigs({ status, checkLevel });
  res.json(configs);
});

// Clear Configs
apiRouter.delete("/configs", (_req: Request, res: Response) => {
  dbStore.clearConfigs();
  res.status(204).end();
});

// List Sources
apiRouter.get("/sources", (_req: Request, res: Response) => {
  res.json(dbStore.getSources());
});

// Create Source
const CreateSourceSchema = z.object({
  name: z.string().min(1),
  url: z.string().min(1),
  type: z.enum(["url", "subscription", "file"]).default("subscription"),
});

apiRouter.post("/sources", (req: Request, res: Response) => {
  const parsed = CreateSourceSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.message });
    return;
  }
  const source = dbStore.addSource(parsed.data);
  res.status(201).json(source);
});

// Delete Source
apiRouter.delete("/sources/:id", (req: Request, res: Response) => {
  const id = parseInt(req.params.id, 10);
  if (isNaN(id)) {
    res.status(400).json({ error: "Invalid source ID" });
    return;
  }
  const success = dbStore.deleteSource(id);
  if (success) {
    res.status(204).end();
  } else {
    res.status(404).json({ error: "Source not found" });
  }
});

// Fetch Single Source
apiRouter.post("/sources/:id/fetch", async (req: Request, res: Response) => {
  const id = parseInt(req.params.id, 10);
  if (isNaN(id)) {
    res.status(400).json({ error: "Invalid source ID" });
    return;
  }

  const source = dbStore.getSourceById(id);
  if (!source) {
    res.status(404).json({ error: "Source not found" });
    return;
  }

  try {
    let text = "";
    if (source.url.startsWith("http://") || source.url.startsWith("https://")) {
      const response = await fetch(source.url, {
        signal: AbortSignal.timeout(15000),
        headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" },
      });
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }
      text = await response.text();
    } else {
      text = "";
    }

    text = tryDecodeBase64(text);
    const parsedList = extractVlessFromText(text);

    // Add country flag and name
    for (const item of parsedList) {
      if (!item.name || item.name.includes("://")) {
        const flag = await getHostFlag(item.host);
        item.name = buildConfigName(flag);
        item.rawUri = rebuildUriWithName(item.rawUri, item.name);
      }
    }

    const result = dbStore.addParsedConfigs(source.id, parsedList);
    res.json(result);
  } catch (err: any) {
    res.status(502).json({ error: err.message || "Failed to fetch source" });
  }
});

// Fetch All Sources
apiRouter.post("/sources/fetch-all", async (_req: Request, res: Response) => {
  const sources = dbStore.getSources().filter((s) => s.enabled);
  let totalFound = 0;
  let totalAdded = 0;

  for (const source of sources) {
    try {
      if (source.url.startsWith("http://") || source.url.startsWith("https://")) {
        const response = await fetch(source.url, {
          signal: AbortSignal.timeout(10000),
          headers: { "User-Agent": "Mozilla/5.0" },
        });
        if (response.ok) {
          let text = await response.text();
          text = tryDecodeBase64(text);
          const parsed = extractVlessFromText(text);
          const result = dbStore.addParsedConfigs(source.id, parsed);
          totalFound += result.found;
          totalAdded += result.added;
        }
      }
    } catch {
      // continue next source
    }
  }

  res.json({ totalFound, totalAdded });
});

// Checker Check
const CheckConfigsSchema = z.object({
  level: z.enum(["tcp", "tls", "http"]),
  concurrency: z.number().int().min(1).max(50).default(10),
  timeoutMs: z.number().int().min(1000).max(30000).default(5000),
  configIds: z.array(z.number().int()).optional(),
});

apiRouter.post("/checker/check", async (req: Request, res: Response) => {
  const parsed = CheckConfigsSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.message });
    return;
  }

  const { level, concurrency, timeoutMs, configIds } = parsed.data;

  if (checkerJobState.running) {
    res.json(checkerJobState);
    return;
  }

  let configsToTest = dbStore.getConfigs();
  if (configIds && configIds.length > 0) {
    configsToTest = configsToTest.filter((c) => configIds.includes(c.id));
  }

  checkerJobState.running = true;
  checkerJobState.level = level;
  checkerJobState.total = configsToTest.length;
  checkerJobState.checked = 0;
  checkerJobState.working = 0;
  checkerJobState.failed = 0;
  checkerJobState.startedAt = new Date().toISOString();

  // Run in background asynchronously
  setImmediate(async () => {
    try {
      const items = configsToTest.map((c) => ({
        id: c.id,
        host: c.host,
        port: c.port,
        sni: c.sni,
        path: c.path,
      }));

      await checkBatch(
        items,
        level,
        concurrency,
        timeoutMs,
        async (id: number, result: CheckResult) => {
          checkerJobState.checked++;
          const isWorking =
            level === "tcp"
              ? result.tcpStatus === "ok"
              : level === "tls"
              ? result.tlsStatus === "ok"
              : result.httpStatus === "ok";

          if (isWorking) checkerJobState.working++;
          else checkerJobState.failed++;

          dbStore.updateConfigCheck(id, result);
        }
      );
    } finally {
      checkerJobState.running = false;
    }
  });

  res.json(checkerJobState);
});

// Checker Status
apiRouter.get("/checker/status", (_req: Request, res: Response) => {
  res.json(checkerJobState);
});

// Export Configs
const ExportConfigsSchema = z.object({
  format: z.enum(["singbox", "xray", "raw"]),
  level: z.enum(["tcp", "tls", "http"]),
  limit: z.number().int().min(1).max(1000).default(100),
});

function toSingBoxOutbound(c: ConfigRecord) {
  return {
    tag: c.name || `vless-${c.id}`,
    type: "vless",
    server: c.host,
    server_port: c.port,
    uuid: c.uuid,
    flow: c.flow || "",
    tls:
      c.security === "tls" || c.security === "reality"
        ? {
            enabled: true,
            server_name: c.sni || c.host,
            insecure: true,
          }
        : undefined,
    transport:
      c.network && c.network !== "tcp"
        ? {
            type: c.network,
            path: c.path || "/",
          }
        : undefined,
  };
}

function toXrayOutbound(c: ConfigRecord) {
  return {
    tag: c.name || `vless-${c.id}`,
    protocol: "vless",
    settings: {
      vnext: [
        {
          address: c.host,
          port: c.port,
          users: [
            {
              id: c.uuid,
              flow: c.flow || "",
              encryption: "none",
            },
          ],
        },
      ],
    },
    streamSettings:
      c.security === "tls" || c.security === "reality"
        ? {
            network: c.network || "tcp",
            security: c.security,
            tlsSettings: {
              serverName: c.sni || c.host,
              allowInsecure: true,
            },
            ...(c.network === "ws" ? { wsSettings: { path: c.path || "/" } } : {}),
          }
        : {
            network: c.network || "tcp",
          },
  };
}

apiRouter.post("/export", (req: Request, res: Response) => {
  const parsed = ExportConfigsSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.message });
    return;
  }

  const { format, level, limit } = parsed.data;

  const configs = dbStore
    .getConfigs({ status: "working", checkLevel: level })
    .slice(0, limit);

  let content = "";
  if (format === "raw") {
    content = configs.map((c) => c.rawUri).join("\n");
  } else if (format === "singbox") {
    const outbounds = configs.map(toSingBoxOutbound);
    content = JSON.stringify({ outbounds }, null, 2);
  } else {
    const outbounds = configs.map(toXrayOutbound);
    content = JSON.stringify({ outbounds }, null, 2);
  }

  res.json({ format, count: configs.length, content });
});

// ── Новые подписки (250/20 БС, BS Top Ping, BS Все) ─────────────────────────
apiRouter.get("/subscriptions", (_req: Request, res: Response) => {
  const subs = [
    {
      id: "250-20bs",
      name: "250 Конфигов (20 БС + 230 Интернет)",
      description: "Ровно 250 рабочих серверов: 20 для белых списков РФ (VK, Yandex, X5, OK, LTE/5G) + 230 скоростных зарубежных",
      file: "sub_250_20bs.txt",
      fileBase64: "sub_250_20bs_base64.txt",
      rawUrl: "/sub/sub_250_20bs.txt",
      base64Url: "/sub/sub_250_20bs_base64.txt",
      count: 250,
      bsCount: 20,
    },
    {
      id: "bs-top-ping",
      name: "BS Top Ping (БС Топ по пингу)",
      description: "Конфиги для обхода белых списков РФ, отсортированные по наименьшей задержке (минимальный пинг)",
      file: "sub_bs_top_ping.txt",
      fileBase64: "sub_bs_top_ping_base64.txt",
      rawUrl: "/sub/sub_bs_top_ping.txt",
      base64Url: "/sub/sub_bs_top_ping_base64.txt",
      count: 200,
      bsCount: 200,
    },
    {
      id: "bs-all",
      name: "BS Все (Все конфиги белых списков)",
      description: "Полный массив всех доступных рабочих конфигураций для белых списков и обхода блокировок",
      file: "sub_bs_all.txt",
      fileBase64: "sub_bs_all_base64.txt",
      rawUrl: "/sub/sub_bs_all.txt",
      base64Url: "/sub/sub_bs_all_base64.txt",
      count: 3046,
      bsCount: 3046,
    },
  ];

  // Update counts from files if they exist
  const enriched = subs.map((s) => {
    const filePath = path.join(process.cwd(), s.file);
    if (fs.existsSync(filePath)) {
      const lines = fs.readFileSync(filePath, "utf-8").split("\n").filter((l) => l.trim() && !l.startsWith("#"));
      return { ...s, count: lines.length };
    }
    return s;
  });

  res.json({ subscriptions: enriched });
});

apiRouter.post("/subscriptions/generate", (_req: Request, res: Response) => {
  exec("python3 generate_subscriptions.py", { cwd: process.cwd() }, (err, stdout, stderr) => {
    if (err) {
      res.status(500).json({ error: stderr || err.message });
      return;
    }
    res.json({ message: "Подписки успешно обновлены", output: stdout });
  });
});

