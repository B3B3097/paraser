import { Router, type IRouter } from "express";
import { eq, sql } from "drizzle-orm";
import { db, vlessConfigsTable } from "@workspace/db";
import { ExportConfigsBody } from "@workspace/api-zod";

const router: IRouter = Router();

function toSingBoxOutbound(c: {
  id: number;
  uuid: string;
  host: string;
  port: number;
  name: string;
  flow: string | null;
  security: string | null;
  sni: string | null;
  network: string | null;
  path: string | null;
}) {
  return {
    tag: c.name || `vless-${c.id}`,
    type: "vless",
    server: c.host,
    server_port: c.port,
    uuid: c.uuid,
    flow: c.flow || "",
    tls: c.security === "tls" || c.security === "reality"
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

function toXrayOutbound(c: {
  id: number;
  uuid: string;
  host: string;
  port: number;
  name: string;
  flow: string | null;
  security: string | null;
  sni: string | null;
  network: string | null;
  path: string | null;
}) {
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
            ...(c.network === "ws"
              ? { wsSettings: { path: c.path || "/" } }
              : {}),
          }
        : {
            network: c.network || "tcp",
          },
  };
}

router.post("/export", async (req, res): Promise<void> => {
  const parsed = ExportConfigsBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.message });
    return;
  }

  const { format, level, limit = 100 } = parsed.data;

  let whereCondition;
  if (level === "tcp") {
    whereCondition = eq(vlessConfigsTable.tcpStatus, "ok");
  } else if (level === "tls") {
    whereCondition = eq(vlessConfigsTable.tlsStatus, "ok");
  } else {
    whereCondition = eq(vlessConfigsTable.httpStatus, "ok");
  }

  const configs = await db
    .select()
    .from(vlessConfigsTable)
    .where(whereCondition)
    .orderBy(sql`${vlessConfigsTable.latencyMs} ASC NULLS LAST`)
    .limit(limit);

  let content: string;

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

export default router;
