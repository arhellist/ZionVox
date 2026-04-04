/**
 * Проверка входящего JSON: разрешены только поля, соответствующие «opaque» нагрузке.
 * Любая попытка передать открытый текст под ожидаемыми именами отклоняется.
 */

const BLOCKED_TOP_LEVEL = new Set([
  "text",
  "plain",
  "plaintext",
  "message",
  "bodyUtf8",
  "decrypted",
  "content"
]);

const REQUIRED_SEALED = ["ivB64", "ciphertextB64"] as const;

export class AuditRejectPlaintextPayload extends Error {
  constructor(reason: string) {
    super(`audit guard: ${reason}`);
    this.name = "AuditRejectPlaintextPayload";
  }
}

export function auditGuardRelayJson(body: unknown): asserts body is Record<string, unknown> {
  if (body === null || typeof body !== "object" || Array.isArray(body)) {
    throw new AuditRejectPlaintextPayload("body must be a JSON object");
  }
  const o = body as Record<string, unknown>;
  for (const k of BLOCKED_TOP_LEVEL) {
    if (k in o) {
      throw new AuditRejectPlaintextPayload(`forbidden field: ${k}`);
    }
  }
  const sealed = o.sealed;
  if (sealed === null || typeof sealed !== "object" || Array.isArray(sealed)) {
    throw new AuditRejectPlaintextPayload("sealed object required");
  }
  const s = sealed as Record<string, unknown>;
  for (const f of REQUIRED_SEALED) {
    if (typeof s[f] !== "string" || !(s[f] as string).length) {
      throw new AuditRejectPlaintextPayload(`sealed.${f} must be non-empty string`);
    }
  }
}
