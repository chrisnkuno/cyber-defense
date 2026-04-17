import http from "node:http";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  buildDashboardState,
  createSimulationDataset,
  listProfiles,
} from "./src/simulation.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const publicDir = path.join(__dirname, "public");

const dataset = createSimulationDataset();

const contentTypes = {
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
};

function sendJson(response, statusCode, payload) {
  response.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
  });
  response.end(JSON.stringify(payload));
}

async function serveStatic(response, requestPath) {
  const normalized = requestPath === "/" ? "/index.html" : requestPath;
  const safePath = path.normalize(normalized).replace(/^(\.\.[/\\])+/, "");
  const filePath = path.join(publicDir, safePath);
  const extension = path.extname(filePath);

  try {
    const contents = await readFile(filePath);
    response.writeHead(200, {
      "Content-Type":
        contentTypes[extension] || "application/octet-stream",
    });
    response.end(contents);
  } catch {
    response.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
    response.end("Not found");
  }
}

const server = http.createServer(async (request, response) => {
  const url = new URL(request.url || "/", "http://localhost");

  if (url.pathname === "/api/profiles") {
    return sendJson(response, 200, {
      generatedAt: dataset.generatedAt,
      profiles: listProfiles(dataset),
    });
  }

  if (url.pathname === "/api/dashboard") {
    const profileId = url.searchParams.get("profile") || dataset.profiles[0].id;
    const tick = Number.parseInt(url.searchParams.get("tick") || "", 10);
    return sendJson(
      response,
      200,
      buildDashboardState(dataset, profileId, Number.isNaN(tick) ? undefined : tick),
    );
  }

  if (url.pathname === "/api/dataset") {
    return sendJson(response, 200, dataset);
  }

  return serveStatic(response, url.pathname);
});

const port = Number.parseInt(process.env.PORT || "3000", 10);
const host = process.env.HOST || "127.0.0.1";

server.listen(port, host, () => {
  console.log(`Cyber defense monitor listening on http://${host}:${port}`);
});
