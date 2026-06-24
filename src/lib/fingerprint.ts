/**
 * Observer-identity fingerprinting.
 *
 * Builds a stable hash from canvas 2D rasterization and WebGL renderer
 * strings. This identifies the *observing* machine (the browser running
 * driftnet), not the remote devices — it is the analyst's identity so that
 * ledgers from different observers can be told apart.
 */

/** Small, fast, non-cryptographic string hash (FNV-1a, 32-bit) rendered hex. */
function fnv1a(input: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < input.length; i++) {
    h ^= input.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  // >>> 0 to coerce to unsigned 32-bit.
  return (h >>> 0).toString(16).padStart(8, "0");
}

function canvasSignature(): string {
  try {
    const canvas = document.createElement("canvas");
    canvas.width = 240;
    canvas.height = 60;
    const ctx = canvas.getContext("2d");
    if (!ctx) return "no-2d";

    ctx.textBaseline = "top";
    ctx.font = "14px 'Courier New', monospace";
    ctx.fillStyle = "#0a0a0a";
    ctx.fillRect(0, 0, 240, 60);
    ctx.fillStyle = "#33ff66";
    ctx.fillText("driftnet::observer//⌘⚡", 4, 8);
    ctx.strokeStyle = "rgba(120,200,255,0.6)";
    ctx.beginPath();
    ctx.arc(120, 30, 18, 0, Math.PI * 1.6);
    ctx.stroke();

    return canvas.toDataURL();
  } catch {
    return "canvas-blocked";
  }
}

function webglSignature(): string {
  try {
    const canvas = document.createElement("canvas");
    const gl =
      (canvas.getContext("webgl") as WebGLRenderingContext | null) ||
      (canvas.getContext("experimental-webgl") as WebGLRenderingContext | null);
    if (!gl) return "no-webgl";

    const dbg = gl.getExtension("WEBGL_debug_renderer_info");
    const vendor = dbg
      ? gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL)
      : gl.getParameter(gl.VENDOR);
    const renderer = dbg
      ? gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL)
      : gl.getParameter(gl.RENDERER);
    const version = gl.getParameter(gl.VERSION);

    return `${vendor}~${renderer}~${version}`;
  } catch {
    return "webgl-blocked";
  }
}

/** Compute the observer fingerprint hash. Cached after first call. */
let cached: string | null = null;

export function observerFingerprint(): string {
  if (cached) return cached;

  const parts = [
    canvasSignature(),
    webglSignature(),
    navigator.userAgent,
    navigator.language,
    `${screen.width}x${screen.height}x${screen.colorDepth}`,
    new Date().getTimezoneOffset().toString(),
    (navigator.hardwareConcurrency ?? 0).toString(),
  ];

  cached = fnv1a(parts.join("|"));
  return cached;
}

export { fnv1a };
