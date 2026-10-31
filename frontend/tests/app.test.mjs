import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, "..");

test("frontend home page exists and defines default export", () => {
  const pagePath = path.join(rootDir, "src", "app", "page.tsx");
  assert.ok(fs.existsSync(pagePath), "src/app/page.tsx must exist");
  const content = fs.readFileSync(pagePath, "utf8");
  assert.match(content, /export default function Home/, "Must export Home component");
  assert.match(content, /Veritor/, "Must reference Veritor");
});

test("frontend root layout exists and defines html/body shell", () => {
  const layoutPath = path.join(rootDir, "src", "app", "layout.tsx");
  assert.ok(fs.existsSync(layoutPath), "src/app/layout.tsx must exist");
  const content = fs.readFileSync(layoutPath, "utf8");
  assert.match(content, /export default function RootLayout/, "Must export RootLayout");
  assert.match(content, /<html/, "Must render html element");
  assert.match(content, /<body/, "Must render body element");
});

test("next.config.ts exists and specifies configuration", () => {
  const configPath = path.join(rootDir, "next.config.ts");
  assert.ok(fs.existsSync(configPath), "next.config.ts must exist");
  const content = fs.readFileSync(configPath, "utf8");
  assert.match(content, /nextConfig/, "Must export NextConfig");
});
