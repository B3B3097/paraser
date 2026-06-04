import { eq, sql } from "drizzle-orm";
import { db, sourcesTable, vlessConfigsTable } from "@workspace/db";
import { extractVlessFromText, tryDecodeBase64 } from "./vless-parser.js";
import { getHostFlag, buildConfigName, rebuildUriWithName } from "./geo.js";
import { logger } from "./logger.js";

const INTERVAL_MS = 60 * 60 * 1000; // 1 hour

async function fetchAndSaveSource(source: { id: number; url: string }): Promise<{ found: number; added: number }> {
  try {
    const response = await fetch(source.url, {
      signal: AbortSignal.timeout(15000),
      headers: { "User-Agent": "Mozilla/5.0" },
    });
    if (!response.ok) return { found: 0, added: 0 };

    let text = await response.text();
    text = tryDecodeBase64(text);

    const parsed = extractVlessFromText(text);
    let added = 0;

    for (const config of parsed) {
      const existing = await db
        .select({ id: vlessConfigsTable.id })
        .from(vlessConfigsTable)
        .where(
          sql`${vlessConfigsTable.uuid} = ${config.uuid} AND ${vlessConfigsTable.host} = ${config.host} AND ${vlessConfigsTable.port} = ${config.port}`,
        )
        .limit(1);

      if (existing.length === 0) {
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
          sourceId: source.id,
          rawUri,
        });
        added++;
      }
    }

    const [total] = await db
      .select({ count: sql<number>`count(*)` })
      .from(vlessConfigsTable)
      .where(eq(vlessConfigsTable.sourceId, source.id));

    await db.update(sourcesTable)
      .set({ lastFetchedAt: new Date(), configCount: Number(total?.count ?? 0) })
      .where(eq(sourcesTable.id, source.id));

    return { found: parsed.length, added };
  } catch (err) {
    logger.error({ err, sourceId: source.id }, "Scheduler: failed to fetch source");
    return { found: 0, added: 0 };
  }
}

export async function runScheduledFetch(): Promise<void> {
  const sources = await db
    .select({ id: sourcesTable.id, url: sourcesTable.url })
    .from(sourcesTable)
    .where(eq(sourcesTable.enabled, true));

  if (sources.length === 0) return;

  logger.info({ count: sources.length }, "Scheduler: starting hourly fetch");

  let totalAdded = 0;
  for (const source of sources) {
    const result = await fetchAndSaveSource(source);
    totalAdded += result.added;
  }

  logger.info({ totalAdded }, "Scheduler: hourly fetch complete");
}

export function startScheduler(): void {
  logger.info({ intervalMs: INTERVAL_MS }, "Scheduler: started — fetching every hour");

  setInterval(() => {
    runScheduledFetch().catch((err) =>
      logger.error({ err }, "Scheduler: unhandled error"),
    );
  }, INTERVAL_MS);
}
