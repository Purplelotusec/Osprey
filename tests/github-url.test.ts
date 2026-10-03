import { describe, it, expect } from "vitest";
import { parseGitHubUrl } from "../src/network/github.js";

describe("parseGitHubUrl", () => {
  it.each([
    ["owner/repo", { owner: "owner", repo: "repo" }],
    ["github.com/owner/repo", { owner: "owner", repo: "repo" }],
    ["https://github.com/owner/repo", { owner: "owner", repo: "repo" }],
    ["https://github.com/owner/repo/", { owner: "owner", repo: "repo" }],
    ["https://www.github.com/owner/repo", { owner: "owner", repo: "repo" }],
    ["https://github.com/owner/repo.git", { owner: "owner", repo: "repo" }],
    ["owner/repo/tree/dev", { owner: "owner", repo: "repo", branch: "dev" }],
    ["https://github.com/owner/repo/tree/main/packages/web", { owner: "owner", repo: "repo", branch: "main", path: "packages/web" }],
  ])("%s", (url, expected) => {
    expect(parseGitHubUrl(url)).toEqual({ branch: undefined, path: undefined, ...expected });
  });

  it("rejects input without an owner and repo", () => {
    expect(() => parseGitHubUrl("just-a-name")).toThrow(/Invalid GitHub URL/);
  });
});
