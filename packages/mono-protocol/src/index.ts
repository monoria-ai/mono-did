export const MONO_HANDSHAKE_PROTOCOL = '/mono/handshake/1.0.0';
export const MONO_JSON_LINE_DELIMITER = '\n';

export function encodeFrame<T>(frame: T): string {
  return `${JSON.stringify(frame)}${MONO_JSON_LINE_DELIMITER}`;
}

export function decodeFrame<T>(line: string): T {
  const parsed = JSON.parse(line) as T;
  if (!parsed || typeof parsed !== 'object' || !('type' in (parsed as Record<string, unknown>))) {
    throw new Error('Invalid mono transport frame');
  }
  return parsed as T;
}
