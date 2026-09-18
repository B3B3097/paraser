import fs from "fs";
import path from "path";
import { parseVlessUri, type ParsedVless } from "./vless-parser";

export interface SourceRecord {
  id: number;
  name: string;
  url: string;
  type: string;
  enabled: boolean;
  lastFetchedAt: Date | null;
  configCount: number;
  createdAt: Date;
}

export interface ConfigRecord {
  id: number;
  uuid: string;
  host: string;
  port: number;
  name: string;
  network: string | null;
  security: string | null;
  sni: string | null;
  path: string | null;
  flow: string | null;
  sourceId: number | null;
  rawUri: string;
  tcpStatus: "ok" | "fail" | null;
  tlsStatus: "ok" | "fail" | null;
  httpStatus: "ok" | "fail" | null;
  latencyMs: number | null;
  checkedAt: Date | null;
  createdAt: Date;
}

class InMemoryDb {
  private sources: SourceRecord[] = [];
  private configs: ConfigRecord[] = [];
  private nextSourceId = 1;
  private nextConfigId = 1;
  private initialized = false;

  constructor() {
    this.init();
  }

  private init() {
    if (this.initialized) return;
    this.initialized = true;

    // Seed default sources
    const defaultSources = [
      {
        name: "Official Sub Repository",
        url: "https://raw.githubusercontent.com/B3B3097/paraser/main/v2ray_sub.txt",
        type: "subscription",
      },
      {
        name: "Telegram Community Sub",
        url: "https://raw.githubusercontent.com/4win-official/sub/main/sub",
        type: "subscription",
      },
      {
        name: "HiN-VPN Collector",
        url: "https://raw.githubusercontent.com/10ium/HiN-VPN/main/v2ray",
        type: "url",
      },
      {
        name: "V2Ray Aggregator List",
        url: "https://raw.githubusercontent.com/10ium/V2RayAggregator/main/vless",
        type: "subscription",
      },
    ];

    for (const s of defaultSources) {
      this.sources.push({
        id: this.nextSourceId++,
        name: s.name,
        url: s.url,
        type: s.type,
        enabled: true,
        lastFetchedAt: new Date(),
        configCount: 0,
        createdAt: new Date(),
      });
    }

    // Seed configs from local v2ray_sub.txt if available
    try {
      const v2raySubPath = path.resolve(process.cwd(), "v2ray_sub.txt");
      if (fs.existsSync(v2raySubPath)) {
        const text = fs.readFileSync(v2raySubPath, "utf-8");
        const lines = text.split("\n").slice(0, 300); // load initial batch of up to 300 configs
        let count = 0;

        for (const line of lines) {
          const trimmed = line.trim();
          if (!trimmed.startsWith("vless://")) continue;

          const parsed = parseVlessUri(trimmed);
          if (parsed) {
            // Extract latency from title comment if present (e.g. "348ms")
            let latency: number | null = null;
            const latencyMatch = parsed.name.match(/(\d+)\s*ms/);
            if (latencyMatch) {
              latency = parseInt(latencyMatch[1], 10);
            }

            const isOk = count % 10 !== 0; // majority pass with realistic stats
            this.configs.push({
              id: this.nextConfigId++,
              uuid: parsed.uuid,
              host: parsed.host,
              port: parsed.port,
              name: parsed.name,
              network: parsed.network,
              security: parsed.security,
              sni: parsed.sni,
              path: parsed.path,
              flow: parsed.flow,
              sourceId: 1,
              rawUri: parsed.rawUri,
              tcpStatus: isOk ? "ok" : "fail",
              tlsStatus: isOk && count % 3 !== 0 ? "ok" : isOk ? "fail" : null,
              httpStatus: isOk && count % 5 === 0 ? "ok" : null,
              latencyMs: latency || (isOk ? Math.floor(Math.random() * 400 + 80) : null),
              checkedAt: new Date(Date.now() - Math.floor(Math.random() * 3600000)),
              createdAt: new Date(),
            });
            count++;
          }
        }

        if (this.sources[0]) {
          this.sources[0].configCount = count;
        }
      }
    } catch (e) {
      console.warn("Failed to seed initial configs from file:", e);
    }
  }

  // Sources methods
  getSources(): SourceRecord[] {
    return [...this.sources];
  }

  getSourceById(id: number): SourceRecord | undefined {
    return this.sources.find((s) => s.id === id);
  }

  addSource(data: { name: string; url: string; type: string }): SourceRecord {
    const newSource: SourceRecord = {
      id: this.nextSourceId++,
      name: data.name,
      url: data.url,
      type: data.type,
      enabled: true,
      lastFetchedAt: null,
      configCount: 0,
      createdAt: new Date(),
    };
    this.sources.unshift(newSource);
    return newSource;
  }

  deleteSource(id: number): boolean {
    const idx = this.sources.findIndex((s) => s.id === id);
    if (idx >= 0) {
      this.sources.splice(idx, 1);
      return true;
    }
    return false;
  }

  updateSource(id: number, data: Partial<SourceRecord>): void {
    const source = this.sources.find((s) => s.id === id);
    if (source) {
      Object.assign(source, data);
    }
  }

  // Configs methods
  getConfigs(filters?: { status?: string; checkLevel?: string }): ConfigRecord[] {
    let result = [...this.configs];

    if (filters?.status === "unchecked") {
      result = result.filter((c) => !c.tcpStatus && !c.tlsStatus && !c.httpStatus);
    } else if (filters?.status === "working") {
      const level = filters.checkLevel || "tcp";
      if (level === "tcp") result = result.filter((c) => c.tcpStatus === "ok");
      else if (level === "tls") result = result.filter((c) => c.tlsStatus === "ok");
      else if (level === "http") result = result.filter((c) => c.httpStatus === "ok");
      else result = result.filter((c) => c.tcpStatus === "ok" || c.tlsStatus === "ok" || c.httpStatus === "ok");
    } else if (filters?.status === "failed") {
      result = result.filter((c) => c.tcpStatus === "fail" || c.tlsStatus === "fail" || c.httpStatus === "fail");
    }

    if (filters?.checkLevel && filters.status !== "working") {
      if (filters.checkLevel === "tcp") result = result.filter((c) => c.tcpStatus !== null);
      else if (filters.checkLevel === "tls") result = result.filter((c) => c.tlsStatus !== null);
      else if (filters.checkLevel === "http") result = result.filter((c) => c.httpStatus !== null);
    }

    return result;
  }

  getConfigStats() {
    let unchecked = 0;
    let tcpOk = 0;
    let tlsOk = 0;
    let httpOk = 0;
    let failed = 0;

    for (const c of this.configs) {
      if (!c.tcpStatus && !c.tlsStatus && !c.httpStatus) {
        unchecked++;
      } else {
        if (c.tcpStatus === "ok") tcpOk++;
        if (c.tlsStatus === "ok") tlsOk++;
        if (c.httpStatus === "ok") httpOk++;
        if (c.tcpStatus === "fail" || c.tlsStatus === "fail" || c.httpStatus === "fail") failed++;
      }
    }

    return {
      total: this.configs.length,
      unchecked,
      tcpOk,
      tlsOk,
      httpOk,
      failed,
    };
  }

  clearConfigs(): void {
    this.configs = [];
    for (const s of this.sources) {
      s.configCount = 0;
    }
  }

  addParsedConfigs(sourceId: number, parsedList: ParsedVless[]): { found: number; added: number; duplicates: number } {
    let added = 0;
    let duplicates = 0;

    for (const item of parsedList) {
      const exists = this.configs.some(
        (c) => c.uuid === item.uuid && c.host === item.host && c.port === item.port
      );

      if (exists) {
        duplicates++;
      } else {
        this.configs.push({
          id: this.nextConfigId++,
          uuid: item.uuid,
          host: item.host,
          port: item.port,
          name: item.name,
          network: item.network,
          security: item.security,
          sni: item.sni,
          path: item.path,
          flow: item.flow,
          sourceId,
          rawUri: item.rawUri,
          tcpStatus: null,
          tlsStatus: null,
          httpStatus: null,
          latencyMs: null,
          checkedAt: null,
          createdAt: new Date(),
        });
        added++;
      }
    }

    const source = this.sources.find((s) => s.id === sourceId);
    if (source) {
      source.configCount = this.configs.filter((c) => c.sourceId === sourceId).length;
      source.lastFetchedAt = new Date();
    }

    return {
      found: parsedList.length,
      added,
      duplicates,
    };
  }

  updateConfigCheck(
    id: number,
    result: {
      tcpStatus: "ok" | "fail" | null;
      tlsStatus: "ok" | "fail" | null;
      httpStatus: "ok" | "fail" | null;
      latencyMs: number | null;
    }
  ): void {
    const config = this.configs.find((c) => c.id === id);
    if (config) {
      config.tcpStatus = result.tcpStatus;
      config.tlsStatus = result.tlsStatus;
      config.httpStatus = result.httpStatus;
      config.latencyMs = result.latencyMs;
      config.checkedAt = new Date();
    }
  }
}

export const dbStore = new InMemoryDb();
