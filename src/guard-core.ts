/** Pure/testable boundary helpers. Nothing here reads, writes or decrypts vault data. */
export function containsCiphertext(text: string): boolean {
  return text.includes('%%folder-lock:') || text.includes('<!--folder-lock:');
}
export function safeMarkdown(text: string, placeholder: string, lockedSource = false): string {
  return lockedSource || containsCiphertext(text) ? placeholder : text;
}
export type AnyMethod = (this: any, ...args: any[]) => any;
export function patchMethod(target: any, name: string, wrap: (old: AnyMethod) => AnyMethod): () => void {
  const old = target?.[name];
  if (typeof old !== 'function') throw new Error(`unsupported:${name}`);
  const own = Object.getOwnPropertyDescriptor(target, name);
  const next = wrap(old);
  Object.defineProperty(target, name, { configurable: true, writable: true, value: next });
  if (target[name] !== next) throw new Error(`unpatchable:${name}`);
  return () => {
    // Do not clobber a method subsequently patched by another plugin.
    if (target[name] !== next) return;
    if (own) Object.defineProperty(target, name, own); else delete target[name];
  };
}
export function collapsedArgument(requested: boolean, locked: boolean): boolean { return locked ? true : requested; }
/** A denied/cancelled/erroring unlock must never call the original file-opening method. */
export async function gatedOpen<T>(authorize: () => Promise<boolean>, original: () => Promise<T>): Promise<T | undefined> {
  try { if (!await authorize()) return undefined; } catch { return undefined; }
  return original();
}
