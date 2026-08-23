const CF4_RESERVED = /[:?&=%]/g;

export function cf4Encode(segment: string): string {
  return segment.replace(CF4_RESERVED, (ch) =>
    `%${ch.charCodeAt(0).toString(16).toUpperCase().padStart(2, "0")}`,
  );
}

export function cf4Decode(segment: string): string {
  return segment.replace(/%[0-9a-fA-F]{2}/g, (hex) =>
    String.fromCharCode(Number.parseInt(hex.slice(1), 16)),
  );
}
