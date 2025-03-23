// eslint-disable-next-line @typescript-eslint/no-var-requires
require("dotenv").config();
import express from "express";

import { registerCommonMiddlewares } from "./middlewares/common";
import { registerMiddleware as registerLocalGit } from "./middlewares/localGit";
import { registerMiddleware as registerLocalFs } from "./middlewares/localFs";
import { createLogger } from "./logger";
import { createPasswordHash } from "./middlewares/utils/htpasswd";
import { writeFileSync } from "fs";

const app = express();
const port = process.env.PORT || 8081;
const level = process.env.LOG_LEVEL || "info";

(async () => {
  // 识别特殊的参数进行生成密码
  const htpasdIndex = process.argv.indexOf("--htpasswd");
  if (htpasdIndex > 1) {
    const [username, password] = process.argv[htpasdIndex + 1].split(":");

    const inPasswordHash = await createPasswordHash(password);

    const htpasswdFile = process.env.HTPASSWD;

    console.log(`Username: ${username}`);
    console.log(`Password: ${inPasswordHash}`);
    if (htpasswdFile) {
      writeFileSync(htpasswdFile, `${username}:${inPasswordHash}\n`, {
        flag: "a",
        encoding: "utf8",
      });
    }

    return 0;
  }

  const logger = createLogger({ level });
  const options = {
    logger,
  };

  registerCommonMiddlewares(app, options);

  // 移除 session 中间件

  // 添加 body-parser 中间件处理表单数据
  app.use(express.urlencoded({ extended: true }));

  try {
    const mode = process.env.MODE || "fs";
    if (mode === "fs") {
      registerLocalFs(app, options);
    } else if (mode === "git") {
      registerLocalGit(app, options);
    } else {
      throw new Error(`Unknown proxy mode '${mode}'`);
    }
  } catch (e) {
    logger.error(e instanceof Error ? e.message : "Unknown error");
    process.exit(1);
  }

  return app.listen(port, () => {
    logger.info(`Decap CMS Proxy Server listening on port ${port}`);
  });
})();
