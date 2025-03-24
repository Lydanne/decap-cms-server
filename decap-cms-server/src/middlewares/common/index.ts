import express from "express";
import morgan from "morgan";
import cors from "cors";

import type winston from "winston";
import htpasswd from "../htpasswd";
import { resolve } from "path";
import { readFile } from "fs/promises";
import { parse, stringify } from "yaml";
import { merge } from "../utils/merge";

export type Options = {
  logger: winston.Logger;
};

export function registerCommonMiddlewares(
  app: express.Express,
  options: Options
) {
  const { logger } = options;
  const stream = {
    write: (message: string) => {
      logger.debug(String(message).trim());
    },
  };
  const staticPath = resolve(__dirname, "..", "static");
  const assetsPath = resolve(__dirname, "..", "assets");
  logger.info("assets: " + assetsPath);
  logger.info("static: " + staticPath);
  app.use(express.static(staticPath));

  app.use("/config.yml", async (req, res) => {
    const defaultConfigPath = resolve(assetsPath, "config.yml");
    const defaultConfigFile = await readFile(defaultConfigPath, "utf-8");

    const configPath = resolve(".", process.env.CONFIG_FILE ?? "config.yml");
    try {
      const configFile = await readFile(configPath, "utf-8");
      const mergedConfig = merge(parse(defaultConfigFile), parse(configFile));

      res.setHeader("Content-Type", "text/yaml");
      res.setHeader("Cache-Control", "no-cache");
      res.setHeader("Pragma", "no-cache");
      res.setHeader("Content-Disposition", "inline; filename=config.yml");

      res.send(stringify(mergedConfig));
    } catch (e) {
      res.status(500).send('{"error": "Failed to read config file"}');
    }
  });

  app.use(htpasswd());
  app.use(morgan("combined", { stream }));
  app.use(cors());
  app.use(express.json({ limit: "50mb" }));
}
