import { eq, sql, isNull } from "drizzle-orm";
import { db, vlessConfigsTable } from "@workspace/db";
import { checkBatch, type CheckLevel, type CheckResult } from "./checker.js";
import { logger } from "./logger.js";

interface JobState {
  running: boolean;
  level: CheckLevel | null;
  total: number;
  checked: number;
  working: number;
  failed: number;
  startedAt: string | null;
}

const state: JobState = {
  running: false,
  level: null,
  total: 0,
  checked: 0,
  working: 0,
  failed: 0,
  startedAt: null,
};

export function getCheckerStatus(): JobState {
  return { ...state };
}

export async function startCheckJob(
  level: CheckLevel,
  concurrency: number,
  timeoutMs: number,
  configIds?: number[],
): Promise<void> {
  if (state.running) return;

  let configs: Array<{ id: number; host: string; port: number; sni: string | null; path: string | null }>;

  if (configIds && configIds.length > 0) {
    configs = await db
      .select({
        id: vlessConfigsTable.id,
        host: vlessConfigsTable.host,
        port: vlessConfigsTable.port,
        sni: vlessConfigsTable.sni,
        path: vlessConfigsTable.path,
      })
      .from(vlessConfigsTable)
      .where(sql`${vlessConfigsTable.id} = ANY(${configIds})`);
  } else {
    configs = await db
      .select({
        id: vlessConfigsTable.id,
        host: vlessConfigsTable.host,
        port: vlessConfigsTable.port,
        sni: vlessConfigsTable.sni,
        path: vlessConfigsTable.path,
      })
      .from(vlessConfigsTable);
  }

  state.running = true;
  state.level = level;
  state.total = configs.length;
  state.checked = 0;
  state.working = 0;
  state.failed = 0;
  state.startedAt = new Date().toISOString();

  logger.info({ level, total: state.total, concurrency }, "Check job started");

  setImmediate(async () => {
    try {
      await checkBatch(
        configs,
        level,
        concurrency,
        timeoutMs,
        async (id: number, result: CheckResult) => {
          state.checked++;

          const isWorking =
            level === "tcp"
              ? result.tcpStatus === "ok"
              : level === "tls"
                ? result.tlsStatus === "ok"
                : result.httpStatus === "ok";

          if (isWorking) state.working++;
          else state.failed++;

          await db
            .update(vlessConfigsTable)
            .set({
              tcpStatus: result.tcpStatus,
              tlsStatus: result.tlsStatus,
              httpStatus: result.httpStatus,
              latencyMs: result.latencyMs,
              checkedAt: new Date(),
            })
            .where(eq(vlessConfigsTable.id, id));
        },
      );
    } catch (err) {
      logger.error({ err }, "Check job error");
    } finally {
      state.running = false;
      logger.info({ checked: state.checked, working: state.working }, "Check job finished");
    }
  });
}
