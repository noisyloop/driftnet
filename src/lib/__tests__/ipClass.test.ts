import { describe, expect, it } from "vitest";
import { classifyIp, ipVersionOf, parseIpv6 } from "../ipClass";

describe("classifyIp — IPv4", () => {
  it("classifies the existing v4 ranges", () => {
    expect(classifyIp("127.0.0.1")).toBe("loopback");
    expect(classifyIp("169.254.10.1")).toBe("link-local");
    expect(classifyIp("10.0.0.5")).toBe("private");
    expect(classifyIp("172.16.0.1")).toBe("private");
    expect(classifyIp("192.168.1.20")).toBe("private");
    expect(classifyIp("100.64.0.1")).toBe("cgnat");
    expect(classifyIp("203.0.113.7")).toBe("public");
  });

  it("rejects malformed v4", () => {
    expect(classifyIp("999.1.1.1")).toBe("unknown");
    expect(classifyIp("not-an-ip")).toBe("unknown");
  });
});

describe("classifyIp — IPv6", () => {
  it("classifies ::1 as loopback", () => {
    expect(classifyIp("::1")).toBe("loopback");
    expect(classifyIp("0:0:0:0:0:0:0:1")).toBe("loopback");
  });

  it("classifies fe80::/10 as link-local", () => {
    expect(classifyIp("fe80::1")).toBe("link-local");
    expect(classifyIp("FE80::abcd:1234")).toBe("link-local");
    expect(classifyIp("febf::1")).toBe("link-local"); // top of /10
    expect(classifyIp("fec0::1")).not.toBe("link-local"); // past /10
  });

  it("classifies fc00::/7 as unique-local", () => {
    expect(classifyIp("fc00::1")).toBe("ula");
    expect(classifyIp("fd12:3456:789a::1")).toBe("ula");
  });

  it("classifies 2000::/3 as public (global unicast)", () => {
    expect(classifyIp("2001:db8:85a3::8a2e:370:7334")).toBe("public");
    expect(classifyIp("2607:f8b0:4004:c07::66")).toBe("public");
    expect(classifyIp("3fff::1")).toBe("public"); // top of /3
  });

  it("strips zone indices before classifying", () => {
    expect(classifyIp("fe80::1%eth0")).toBe("link-local");
  });

  it("returns unknown for malformed or unassigned v6", () => {
    expect(classifyIp("::")).toBe("unknown"); // unspecified
    expect(classifyIp("1:::2")).toBe("unknown");
    expect(classifyIp("12345::1")).toBe("unknown");
    expect(classifyIp("g::1")).toBe("unknown");
  });
});

describe("classifyIp — mDNS", () => {
  it("flags .local candidate hostnames as obscured", () => {
    expect(classifyIp("a1b2c3d4-e5f6-7890.local")).toBe("obscured");
    expect(classifyIp("SOMETHING.LOCAL")).toBe("obscured");
  });
});

describe("parseIpv6", () => {
  it("expands :: compression to 8 groups", () => {
    expect(parseIpv6("2001:db8::1")).toEqual([
      0x2001, 0xdb8, 0, 0, 0, 0, 0, 1,
    ]);
  });

  it("handles an embedded IPv4 tail", () => {
    expect(parseIpv6("::ffff:192.0.2.1")).toEqual([
      0, 0, 0, 0, 0, 0xffff, 0xc000, 0x0201,
    ]);
  });

  it("rejects too many groups", () => {
    expect(parseIpv6("1:2:3:4:5:6:7:8:9")).toBeNull();
    expect(parseIpv6("1:2:3:4:5:6:7:8::")).toBeNull();
  });
});

describe("ipVersionOf", () => {
  it("distinguishes families by colon", () => {
    expect(ipVersionOf("192.168.1.1")).toBe(4);
    expect(ipVersionOf("2001:db8::1")).toBe(6);
  });
});
