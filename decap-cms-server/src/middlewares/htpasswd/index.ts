import type { Handler, Request, Response } from "express";
import express from "express";
import { jwtDecode } from "jwt-decode";
import bcrypt from "bcrypt";
import { readFile } from "fs/promises"; // 使用 Promise 版本的 readFile
import crypto from "crypto";
import jwt from "jsonwebtoken";

// const formdata = multer().none(); // 创建一个 multer 实例，用于处理 multipart/form-data
const formdata = express.urlencoded({ extended: true });

interface JwtPayload {
  sub?: string;
  user?: string;
  username?: string;
  email?: string;
}

/**
 * 生成登录页面 HTML
 * @param originalUrl
 * @param errorMessage
 * @returns
 */
function generateLoginPage(originalUrl: string, errorMessage: string = "") {
  return `
  <!DOCTYPE html>
  <html lang="en">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Decap CMS - Login</title>
    <style>
      body {
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        background-color: #f5f5f5;
        display: flex;
        align-items: center;
        justify-content: center;
        height: 100vh;
        margin: 0;
        padding: 0;
      }
      .login-container {
        background-color: white;
        border-radius: 5px;
        box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
        padding: 30px;
        width: 350px;
      }
      h1 {
        margin-top: 0;
        color: #333;
        text-align: center;
      }
      .error-message {
        color: #d32f2f;
        margin-bottom: 20px;
        text-align: center;
      }
      form {
        display: flex;
        flex-direction: column;
      }
      label {
        margin-bottom: 5px;
        color: #555;
      }
      input {
        padding: 10px;
        margin-bottom: 15px;
        border: 1px solid #ddd;
        border-radius: 4px;
        font-size: 16px;
      }
      button {
        background-color: #2e7d32;
        color: white;
        border: none;
        padding: 12px;
        border-radius: 4px;
        cursor: pointer;
        font-size: 16px;
      }
      button:hover {
        background-color: #1b5e20;
      }
    </style>
  </head>
  <body>
    <div class="login-container">
      <h1>Decap CMS Admin</h1>
      ${errorMessage ? `<p class="error-message">${errorMessage}</p>` : ""}
      <form action="/auth/login" method="POST">
        <input type="hidden" name="originalUrl" value="${originalUrl}">
        <label for="username">Username</label>
        <input type="text" id="username" name="username" required autofocus>
        <label for="password">Password</label>
        <input type="password" id="password" name="password" required>
        <button type="submit">Log In</button>
      </form>
    </div>
  </body>
  </html>
  `;
}

// 缓存 htpasswd 内容，避免频繁文件读取
let htpasswdCache: { content: string; timestamp: number } | null = null;
const CACHE_TTL = 24 * 60 * 60 * 1000; // 24H缓存

// 读取 htpasswd 文件，带缓存
async function readHtpasswdFile(filePath: string): Promise<string> {
  // 检查是否有有效缓存
  const now = Date.now();
  if (htpasswdCache && now - htpasswdCache.timestamp < CACHE_TTL) {
    return htpasswdCache.content;
  }

  try {
    const content = await readFile(filePath, "utf8");
    // 更新缓存
    htpasswdCache = {
      content,
      timestamp: now,
    };
    return content;
  } catch (error) {
    console.error(`Error reading htpasswd file (${filePath}):`, error);
    throw new Error("Failed to read htpasswd file");
  }
}

// 验证 htpasswd 用户凭据的函数
async function validateCredentials(
  username: string,
  password: string,
  htpasswdData: string
): Promise<boolean> {
  const htpasswdLines = htpasswdData
    .split("\n")
    .filter((line) => line.trim() !== "");
  const userEntry = htpasswdLines.find((line) =>
    line.startsWith(`${username}:`)
  );

  if (!userEntry) {
    console.log(`User '${username}' not found in htpasswd file`);
    return false;
  }

  const [_, passwordHash] = userEntry.split(":", 2);

  try {
    if (passwordHash.startsWith("$2")) {
      // bcrypt 格式
      return await bcrypt.compare(password, passwordHash);
    } else if (
      passwordHash.startsWith("$apr1$") ||
      passwordHash.startsWith("$1$")
    ) {
      // Apache MD5 或标准 MD5 格式 - 这里简化处理
      console.warn(
        "MD5 hash format detected. Consider upgrading to bcrypt for better security."
      );
      const md5Hash = crypto.createHash("md5").update(password).digest("hex");
      return (
        md5Hash === passwordHash.substring(passwordHash.lastIndexOf("$") + 1)
      );
    } else {
      // 纯文本或其他未识别格式
      console.warn(
        "Plain text or unknown password format detected for user:",
        username
      );
      return password === passwordHash;
    }
  } catch (error) {
    console.error("Error validating credentials:", error);
    return false;
  }
}

// 从 cookie 中获取 JWT 令牌
function getTokenFromCookie(req: Request): string | null {
  const cookieHeader = req.headers.cookie;
  if (!cookieHeader) return null;

  const cookies = cookieHeader.split(";").map((cookie) => cookie.trim());
  const authCookie = cookies.find((cookie) => cookie.startsWith("decapAuth="));

  if (!authCookie) return null;
  return authCookie.split("=")[1];
}

// 从请求中获取 JWT 令牌（尝试从 Authorization 头或 Cookie 中获取）
function getToken(req: Request): string | null {
  // 首先尝试从 Authorization 头中获取
  const authHeader = req.headers.authorization;
  if (authHeader?.startsWith("Bearer ")) {
    return authHeader.split("Bearer ")[1];
  }

  // 然后尝试从 cookie 中获取
  return getTokenFromCookie(req);
}

// 验证 JWT 令牌
function verifyToken(token: string): { valid: boolean; username?: string } {
  try {
    const secret = process.env.JWT_SECRET || "decap-cms-secret";
    const decoded = jwt.verify(token, secret) as { username: string };
    return { valid: true, username: decoded.username };
  } catch (error) {
    console.log("Token verification failed:", error);
    return { valid: false };
  }
}

export default function htpasswd(): Handler {
  return async (req, res, next) => {
    // 如果请求路径是登录表单提交，跳过认证检查
    if (req.path === "/auth/login" && req.method === "POST") {
      formdata(req, res, async () => {
        handleLogin()(req, res, next);
      });
      return;
    }

    try {
      // 获取令牌
      const token = getToken(req);

      // 如果有令牌，验证它
      if (token) {
        const { valid, username } = verifyToken(token);
        if (valid && username) {
          console.log(`User '${username}' authenticated with token`);
          // 令牌有效，继续处理请求
          return next();
        }
        console.log(
          "Invalid token, proceeding to other authentication methods"
        );
      }

      // 尝试 API Key 认证 (适用于 API 调用)
      const jwtToken = req.headers.authorization?.split("Bearer ")[1];

      if (jwtToken) {
        try {
          const htpasswdPath = process.env.HTPASSWD;
          if (!htpasswdPath) {
            console.error("HTPASSWD environment variable is not set");
            return res
              .status(500)
              .json({ error: "Server configuration error" });
          }

          const htpasswd = await readHtpasswdFile(htpasswdPath);

          // 解析 JWT 获取用户凭据
          const decoded = jwtDecode<JwtPayload>(jwtToken);
          const username =
            decoded.sub || decoded.user || decoded.username || decoded.email;

          if (!username) {
            return res
              .status(401)
              .json({ error: "Invalid JWT token - missing username" });
          }

          // 此处不应验证密码，因为 JWT 本身已经是有效的认证令牌
          // 只需验证用户是否存在于 htpasswd 文件中
          const userExists = htpasswd
            .split("\n")
            .some((line) => line.startsWith(`${username}:`));

          if (userExists) {
            // 认证成功，创建我们自己的 JWT 令牌
            const secret = process.env.JWT_SECRET || "decap-cms-secret";
            const token = jwt.sign({ username }, secret, { expiresIn: "24h" });

            // 设置 cookie
            res.setHeader(
              "Set-Cookie",
              `decapAuth=${token}; Path=/; HttpOnly; Max-Age=86400; SameSite=Strict`
            );

            return next();
          } else {
            return res.status(401).json({ error: "User not found" });
          }
        } catch (error) {
          console.error("JWT authentication error:", error);
          return res.status(401).json({ error: "Authentication failed" });
        }
      }

      // 如果是 API 请求，返回 401 而不是登录页面
      if (req.xhr || req.headers.accept?.includes("application/json")) {
        return res.status(401).json({ error: "Authentication required" });
      }

      // 没有有效认证，返回登录页面
      return res.send(generateLoginPage(req.originalUrl || req.url));
    } catch (error) {
      console.error("Authentication error:", error);
      // 如果是 API 请求，返回 JSON 错误
      if (req.xhr || req.headers.accept?.includes("application/json")) {
        return res.status(500).json({ error: "Authentication system error" });
      }
      return res.send(
        generateLoginPage(
          req.originalUrl || req.url,
          "Authentication system error"
        )
      );
    }
  };
}

// 处理登录表单提交的处理器
export function handleLogin(): Handler {
  return async (req, res) => {
    try {
      const { username, password, originalUrl } = req.body;

      if (!username || !password) {
        return res
          .status(400)
          .send(
            generateLoginPage(
              originalUrl || "",
              "Username and password are required"
            )
          );
      }

      const htpasswdPath = process.env.HTPASSWD;
      if (!htpasswdPath) {
        console.error("HTPASSWD environment variable is not set");
        return res
          .status(500)
          .send(
            generateLoginPage(originalUrl || "", "Server configuration error")
          );
      }

      const htpasswd = await readHtpasswdFile(htpasswdPath);

      // 验证用户凭据
      const isValid = await validateCredentials(username, password, htpasswd);

      if (isValid) {
        console.log(`User '${username}' login successful`);
        // 认证成功，创建 JWT 令牌
        const secret = process.env.JWT_SECRET || "decap-cms-secret";
        const token = jwt.sign({ username }, secret, { expiresIn: "24h" });

        // 设置 cookie
        res.setHeader(
          "Set-Cookie",
          `decapAuth=${token}; Path=/; HttpOnly; Max-Age=86400; SameSite=Strict`
        );

        // 重定向回原始页面
        return res.redirect(originalUrl || "/");
      } else {
        console.log(`Login failed for user '${username}'`);
        // 认证失败，返回登录页面并显示错误
        return res
          .status(401)
          .send(
            generateLoginPage(
              originalUrl || "/",
              "Invalid username or password"
            )
          );
      }
    } catch (error) {
      console.error("Login error:", error);
      return res
        .status(500)
        .send(
          generateLoginPage(
            req.body.originalUrl || "/",
            "Authentication system error"
          )
        );
    }
  };
}
