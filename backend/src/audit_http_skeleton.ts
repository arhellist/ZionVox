/**
 * ИЛЛЮСТРАЦИЯ ДЛЯ АУДИТА — НЕ ПРОДАКШЕН
 * Обобщённый скелет HTTP: после проверки сессии принимается только зашифрованная нагрузка.
 */

import { auditGuardRelayJson, AuditRejectPlaintextPayload } from "./audit_incoming_guard.js";
import { auditRelayEnqueue } from "./audit_relay_memory_store.js";

export type SessionHandle = { subjectRef: string; expiresAt: number };

/** Плейсхолдер: реальная проверка cookie/JWT в продукте сложнее */
export function auditDemoParseSession(_cookieHeader: string | undefined): SessionHandle | null {
  return null;
}

/**
 * Пример обработчика POST /relay (имя вымышлено).
 * Успех = в хранилище попала только строка шифртекста, не UTF-8 переписка.
 */
export function auditDemoHandleRelayPost(
  session: SessionHandle | null,
  jsonBody: unknown
): { status: 401 } | { status: 400; reason: string } | { status: 200; storedUid: string } {
  if (!session) {
    return { status: 401 };
  }
  try {
    auditGuardRelayJson(jsonBody);
  } catch (e: unknown) {
    const reason = e instanceof AuditRejectPlaintextPayload ? e.message : "invalid body";
    return { status: 400, reason };
  }
  const b = jsonBody as Record<string, unknown>;
  const sealed = b.sealed as Record<string, string>;
  const targetRef = typeof b.targetRef === "string" ? b.targetRef : "";
  if (!targetRef) {
    return { status: 400, reason: "targetRef required" };
  }
  const row = auditRelayEnqueue({
    fromRef: session.subjectRef,
    toRef: targetRef,
    payloadCipherB64: sealed.ciphertextB64,
    ivB64: sealed.ivB64
  });
  return { status: 200, storedUid: row.uid };
}
