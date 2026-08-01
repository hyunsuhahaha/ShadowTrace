import { describe, expect, it } from "vitest";
import config from "../vite.config";

describe("development proxy", () => {
  it("forwards interactive terminal WebSockets", () => {
    const value = config as any;
    expect(value.server?.proxy?.["/api"]).toMatchObject({ ws: true });
  });
});
