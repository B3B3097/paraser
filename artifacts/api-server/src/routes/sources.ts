import { Router, type IRouter } from "express";
import { eq, sql } from "drizzle-orm";
import { db, sourcesTable, vlessConfigsTable } from "@workspace/db";
import {
  CreateSourceBody,
  DeleteSourceParams,
  FetchSourceParams,
} from "@workspace/api-zod";
import { extractVlessFromText, tryDecodeBase64 } from "../lib/vless-parser.js";
import { getHostFlag, buildConfigName, rebuildUriWithName } from "../lib/geo.js";

const router: IRouter = Router();

router.get("/sources", async (_req, res): Promise<void> => {
  const sources = await db.select().from(sourcesTable).orderBy(sourcesTable.createdAt);
  res.json(sources.map((s) => ({
    ...s,
    lastFetchedAt: s.lastFetchedAt?.toISOString() ?? null,
    createdAt: s.createdAt.toISOString(),
  })));
});

router.post("/sources", async (req, res): Promise<void> => {
  const parsed = CreateSourceBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.message });
    return;
  }

  const [source] = await db
    .insert(sourcesTable)
    .values(parsed.data)
    .returning();

  res.status(201).json({
    ...source,
    lastFetchedAt: source.lastFetchedAt?.toISOString() ?? null,
    createdAt: source.createdAt.toISOString(),
  });
});

router.delete("/sources/:id", async (req, res): Promise<void> => {
  const raw = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
  const params = DeleteSourceParams.safeParse({ id: raw });
  if (!params.success) {
    res.status(400).json({ error: params.error.message });
    return;
  }

  await db.delete(sourcesTable).where(eq(sourcesTable.id, params.data.id));
  res.sendStatus(204);
});

async function doFetch(sourceId: number, url: string): Promise<{ found: number; added: number; duplicates: number; error: string | null }> {
  try {
    const response = await fetch(url, {
      signal: AbortSignal.timeout(15000),
      headers: { "User-Agent": "Mozilla/5.0" },
    });

    if (!response.ok) {
      return { found: 0, added: 0, duplicates: 0, error: `HTTP ${response.status}` };
    }

    let text = await response.text();
    text = tryDecodeBase64(text);

    const parsed = extractVlessFromText(text);
    if (parsed.length === 0) {
      await db.update(sourcesTable)
        .set({ lastFetchedAt: new Date(), configCount: 0 })
        .where(eq(sourcesTable.id, sourceId));
      return { found: 0, added: 0, duplicates: 0, error: null };
    }

    let added = 0;
    let duplicates = 0;

    for (const config of parsed) {
      const existing = await db
        .select({ id: vlessConfigsTable.id })
        .from(vlessConfigsTable)
        .where(
          sql`${vlessConfigsTable.uuid} = ${config.uuid} AND ${vlessConfigsTable.host} = ${config.host} AND ${vlessConfigsTable.port} = ${config.port}`,
        )
        .limit(1);

      if (existing.length > 0) {
        duplicates++;
      } else {
        const flag = await getHostFlag(config.host);
        const name = buildConfigName(flag);
        const rawUri = rebuildUriWithName(config.rawUri, name);
        await db.insert(vlessConfigsTable).values({
          uuid: config.uuid,
          host: config.host,
          port: config.port,
          name,
          network: config.network,
          security: config.security,
          sni: config.sni,
          path: config.path,
          flow: config.flow,
          sourceId,
          rawUri,
        });
        added++;
      }
    }

    const total = await db
      .select({ count: sql<number>`count(*)` })
      .from(vlessConfigsTable)
      .where(eq(vlessConfigsTable.sourceId, sourceId));

    await db.update(sourcesTable)
      .set({ lastFetchedAt: new Date(), configCount: Number(total[0]?.count ?? 0) })
      .where(eq(sourcesTable.id, sourceId));

    return { found: parsed.length, added, duplicates, error: null };
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return { found: 0, added: 0, duplicates: 0, error: message };
  }
}

router.post("/sources/:id/fetch", async (req, res): Promise<void> => {
  const raw = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
  const params = FetchSourceParams.safeParse({ id: raw });
  if (!params.success) {
    res.status(400).json({ error: params.error.message });
    return;
  }

  const [source] = await db
    .select()
    .from(sourcesTable)
    .where(eq(sourcesTable.id, params.data.id))
    .limit(1);

  if (!source) {
    res.status(404).json({ error: "Source not found" });
    return;
  }

  const result = await doFetch(source.id, source.url);
  res.json({ sourceId: source.id, ...result });
});

router.post("/sources/fetch-all", async (_req, res): Promise<void> => {
  const sources = await db.select().from(sourcesTable).where(eq(sourcesTable.enabled, true));

  let totalFound = 0;
  let totalAdded = 0;
  let totalDuplicates = 0;
  const results = [];

  for (const source of sources) {
    const result = await doFetch(source.id, source.url);
    totalFound += result.found;
    totalAdded += result.added;
    totalDuplicates += result.duplicates;
    results.push({ sourceId: source.id, ...result });
  }

  res.json({ totalFound, totalAdded, totalDuplicates, results });
});

export default router;
