import { Router, type IRouter } from "express";
import healthRouter from "./health.js";
import sourcesRouter from "./sources.js";
import configsRouter from "./configs.js";
import checkerRouter from "./checker.js";
import exportRouter from "./export.js";
import tpsuRouter from "./tpsu.js";

const router: IRouter = Router();

router.use(healthRouter);
router.use(sourcesRouter);
router.use(configsRouter);
router.use(checkerRouter);
router.use(exportRouter);
router.use(tpsuRouter);

export default router;
