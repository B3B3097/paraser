import express from "express";
import cors from "cors";
import path from "path";
import fs from "fs";
import { createServer as createViteServer } from "vite";
import { apiRouter } from "./server/routes";

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(cors());
  app.use(express.json({ limit: "50mb" }));
  app.use(express.urlencoded({ extended: true, limit: "50mb" }));

  // API routes FIRST
  app.use("/api", apiRouter);

  // Subscription files endpoint for v2rayNG, Happ, NekoBox, Hiddify, v2RayTun
  const handleSubFile = (filename: string, res: express.Response) => {
    // Sanitize filename to prevent path traversal
    const safeName = path.basename(filename);
    const filePath = path.join(process.cwd(), safeName);
    if (fs.existsSync(filePath)) {
      res.setHeader("Content-Type", "text/plain; charset=utf-8");
      res.setHeader("profile-update-interval", "1");
      res.setHeader("subscription-userinfo", "upload=0; download=0; total=1099511627776; expire=4102444800");
      res.sendFile(filePath);
    } else {
      res.status(404).send(`Subscription file ${safeName} not found`);
    }
  };

  app.get("/sub/:filename", (req, res) => {
    handleSubFile(req.params.filename, res);
  });

  app.get("/sub_:type.txt", (req, res) => {
    handleSubFile(`sub_${req.params.type}.txt`, res);
  });

  app.get("/sub_:type_base64.txt", (req, res) => {
    handleSubFile(`sub_${req.params.type}_base64.txt`, res);
  });

  // Vite middleware for development
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (_req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://0.0.0.0:${PORT}`);
  });
}

startServer();
