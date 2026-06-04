import { Router, type IRouter } from "express";
import { CheckConfigsBody } from "@workspace/api-zod";
import { getCheckerStatus, startCheckJob } from "../lib/checker-job.js";
import type { CheckLevel } from "../lib/checker.js";

const router: IRouter = Router();

router.post("/checker/check", async (req, res): Promise<void> => {
  const parsed = CheckConfigsBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.message });
    return;
  }

  const { level, concurrency = 10, timeoutMs = 5000, configIds } = parsed.data;

  await startCheckJob(level as CheckLevel, concurrency, timeoutMs, configIds);

  res.json(getCheckerStatus());
});

router.get("/checker/status", async (_req, res): Promise<void> => {
  res.json(getCheckerStatus());
});

export default router;
