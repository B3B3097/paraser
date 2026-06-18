import { Router, type IRouter } from "express";
import fs from "fs";
import path from "path";

const router: IRouter = Router();

interface TPSUStats {
  version: string;
  blocked_asns: number;
  bad_fingerprints: number;
  good_fingerprints: string[];
  experimental_fp: string[];
  safe_front_sni: number;
  blacklist_sni: number;
  stats_json: Record<string, unknown> | null;
}

router.get("/tpsu", (_req, res) => {
  const data: TPSUStats = {
    version: "v3.0 Siberian+",
    blocked_asns: 18,
    bad_fingerprints: 14,
    good_fingerprints: ["firefox", "edge", "android", "360", "qq"],
    experimental_fp: ["cnsa", "opera", "brave", "vivaldi", "duckduckgo"],
    safe_front_sni: 24,
    blacklist_sni: 15,
    stats_json: null,
  };

  try {
    const statsPath = path.resolve("stats.json");
    if (fs.existsSync(statsPath)) {
      data.stats_json = JSON.parse(fs.readFileSync(statsPath, "utf-8"));
    }
  } catch {
    // stats.json not available
  }

  res.json(data);
});

export default router;
