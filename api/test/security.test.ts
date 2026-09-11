import { describe, expect, it } from "vitest";
import { isPublicIp } from "../src/security";

describe("public IP policy", () => {
  it("rejects the well-known NAT64 prefix 64:ff9b::/96", () => {
    expect(isPublicIp("64:ff9b::c000:201")).toBe(false);
    expect(isPublicIp("64:ff9b:0:0:0:0:c000:201")).toBe(false);
    expect(isPublicIp("64:ff9b::")).toBe(false);
  });

  it("rejects the local-use NAT64 prefix 64:ff9b:1::/48", () => {
    expect(isPublicIp("64:ff9b:1::1")).toBe(false);
    expect(isPublicIp("64:ff9b:1:0:0:0:0:1")).toBe(false);
  });

  it("still allows a typical public IPv6 address", () => {
    expect(isPublicIp("2001:4860:4860::8888")).toBe(true);
  });
});
