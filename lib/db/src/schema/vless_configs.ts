import { pgTable, text, serial, timestamp, integer } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";

export const vlessConfigsTable = pgTable("vless_configs", {
  id: serial("id").primaryKey(),
  uuid: text("uuid").notNull(),
  host: text("host").notNull(),
  port: integer("port").notNull(),
  name: text("name").notNull().default(""),
  network: text("network"),
  security: text("security"),
  sni: text("sni"),
  path: text("path"),
  flow: text("flow"),
  sourceId: integer("source_id"),
  tcpStatus: text("tcp_status"),
  tlsStatus: text("tls_status"),
  httpStatus: text("http_status"),
  latencyMs: integer("latency_ms"),
  checkedAt: timestamp("checked_at", { withTimezone: true }),
  rawUri: text("raw_uri").notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export const insertVlessConfigSchema = createInsertSchema(vlessConfigsTable).omit({ id: true, createdAt: true });
export type InsertVlessConfig = z.infer<typeof insertVlessConfigSchema>;
export type VlessConfig = typeof vlessConfigsTable.$inferSelect;
