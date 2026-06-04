import { Router, type IRouter } from "express";
import { eq, sql, and, isNotNull } from "drizzle-orm";
import { db, vlessConfigsTable } from "@workspace/db";
import { ListConfigsQueryParams, GetConfigParams } from "@workspace/api-zod";

const router: IRouter = Router();

router.get("/configs", async (req, res): Promise<void> => {
  const parsed = ListConfigsQueryParams.safeParse(req.query);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.message });
    return;
  }

  const { status, checkLevel } = parsed.data;

  const conditions = [];

  if (status === "unchecked") {
    conditions.push(sql`${vlessConfigsTable.tcpStatus} IS NULL`);
  } else if (status === "working") {
    if (checkLevel === "tcp") {
      conditions.push(eq(vlessConfigsTable.tcpStatus, "ok"));
    } else if (checkLevel === "tls") {
      conditions.push(eq(vlessConfigsTable.tlsStatus, "ok"));
    } else if (checkLevel === "http") {
      conditions.push(eq(vlessConfigsTable.httpStatus, "ok"));
    } else {
      conditions.push(sql`(${vlessConfigsTable.tcpStatus} = 'ok' OR ${vlessConfigsTable.tlsStatus} = 'ok' OR ${vlessConfigsTable.httpStatus} = 'ok')`);
    }
  } else if (status === "failed") {
    conditions.push(sql`${vlessConfigsTable.tcpStatus} IS NOT NULL`);
    conditions.push(sql`${vlessConfigsTable.tcpStatus} != 'ok' AND (${vlessConfigsTable.tlsStatus} IS NULL OR ${vlessConfigsTable.tlsStatus} != 'ok') AND (${vlessConfigsTable.httpStatus} IS NULL OR ${vlessConfigsTable.httpStatus} != 'ok')`);
  }

  const where = conditions.length > 0 ? and(...conditions) : undefined;

  const configs = await db
    .select()
    .from(vlessConfigsTable)
    .where(where)
    .orderBy(vlessConfigsTable.createdAt)
    .limit(500);

  res.json(
    configs.map((c) => ({
      ...c,
      checkedAt: c.checkedAt?.toISOString() ?? null,
      createdAt: c.createdAt.toISOString(),
    })),
  );
});

router.delete("/configs", async (_req, res): Promise<void> => {
  await db.delete(vlessConfigsTable);
  res.sendStatus(204);
});

router.get("/configs/stats", async (_req, res): Promise<void> => {
  const [row] = await db
    .select({
      total: sql<number>`count(*)`,
      unchecked: sql<number>`count(*) filter (where ${vlessConfigsTable.tcpStatus} is null)`,
      tcpOk: sql<number>`count(*) filter (where ${vlessConfigsTable.tcpStatus} = 'ok')`,
      tlsOk: sql<number>`count(*) filter (where ${vlessConfigsTable.tlsStatus} = 'ok')`,
      httpOk: sql<number>`count(*) filter (where ${vlessConfigsTable.httpStatus} = 'ok')`,
      failed: sql<number>`count(*) filter (where ${vlessConfigsTable.tcpStatus} = 'fail')`,
    })
    .from(vlessConfigsTable);

  res.json({
    total: Number(row?.total ?? 0),
    unchecked: Number(row?.unchecked ?? 0),
    tcpOk: Number(row?.tcpOk ?? 0),
    tlsOk: Number(row?.tlsOk ?? 0),
    httpOk: Number(row?.httpOk ?? 0),
    failed: Number(row?.failed ?? 0),
  });
});

router.get("/configs/:id", async (req, res): Promise<void> => {
  const raw = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
  const params = GetConfigParams.safeParse({ id: raw });
  if (!params.success) {
    res.status(400).json({ error: params.error.message });
    return;
  }

  const [config] = await db
    .select()
    .from(vlessConfigsTable)
    .where(eq(vlessConfigsTable.id, params.data.id))
    .limit(1);

  if (!config) {
    res.status(404).json({ error: "Config not found" });
    return;
  }

  res.json({
    ...config,
    checkedAt: config.checkedAt?.toISOString() ?? null,
    createdAt: config.createdAt.toISOString(),
  });
});

export default router;
