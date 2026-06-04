# VLESS Parser

A tool for collecting, parsing and testing VLESS proxy configs from URL/subscription sources with multi-level connectivity checks and export to Sing-Box/Xray formats.

## Run & Operate

- `pnpm --filter @workspace/api-server run dev` — run the API server (port 5000)
- `pnpm --filter @workspace/vless-parser run dev` — run the frontend
- `pnpm run typecheck` — full typecheck across all packages
- `pnpm run build` — typecheck + build all packages
- `pnpm --filter @workspace/api-spec run codegen` — regenerate API hooks and Zod schemas from the OpenAPI spec
- `pnpm --filter @workspace/db run push` — push DB schema changes (dev only)
- Required env: `DATABASE_URL` — Postgres connection string

## Stack

- pnpm workspaces, Node.js 24, TypeScript 5.9
- Frontend: React + Vite, Tailwind CSS, shadcn/ui, TanStack Query
- API: Express 5
- DB: PostgreSQL + Drizzle ORM
- Validation: Zod (`zod/v4`), `drizzle-zod`
- API codegen: Orval (from OpenAPI spec)
- Build: esbuild (CJS bundle)

## Where things live

- `lib/api-spec/openapi.yaml` — API contract (source of truth)
- `lib/db/src/schema/` — DB tables: `sources.ts`, `vless_configs.ts`
- `artifacts/api-server/src/routes/` — sources, configs, checker, export routes
- `artifacts/api-server/src/lib/` — `vless-parser.ts`, `checker.ts`, `checker-job.ts`
- `artifacts/vless-parser/src/pages/` — Dashboard, Sources, Configs, Checker, Export

## Architecture decisions

- Check levels are progressive: TCP → TCP+TLS → TCP+TLS+HTTP. Each level builds on the previous.
- The checker runs in the background using `setImmediate` and updates DB records in real-time.
- Frontend polls `/checker/status` every 1.5s when `running=true`.
- VLESS parsing supports base64-encoded subscriptions (auto-detects and decodes).
- Export sorts working configs by latency ASC so fastest configs appear first.

## Product

- Add URL/subscription sources and fetch VLESS configs from them
- Run connectivity checks at TCP, TLS, or HTTP level with configurable concurrency/timeout
- View all parsed configs with status badges and latency
- Export working configs in Sing-Box JSON, Xray JSON, or raw VLESS URI format

## User preferences

_Populate as you build._

## Gotchas

- The checker job state is in-memory — restarts the server resets progress display (results are still saved to DB)
- Orval body schema naming: use entity-shaped names (e.g. `SourceInput`), not operation-shaped (`CreateSourceBody`) to avoid TS2308 collisions
- `@import url(...)` in index.css MUST be the very first line before `@import "tailwindcss"`

## Pointers

- See the `pnpm-workspace` skill for workspace structure, TypeScript setup, and package details
