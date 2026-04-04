/**
 * Упрощённое in-memory хранилище для аудита: демонстрирует, что в памяти/«БД»
 * лежат только поля из AuditRelayQueueRow — без расшифровки и без текстового столбца.
 */

import { randomBytes } from "node:crypto";
import type { AuditRelayQueueRow } from "./audit_relay_schema.js";

const bucket: AuditRelayQueueRow[] = [];

export function auditRelayEnqueue(row: Omit<AuditRelayQueueRow, "createdIso" | "uid"> & { uid?: string }): AuditRelayQueueRow {
  const uid = row.uid ?? cryptoRandomId();
  const full: AuditRelayQueueRow = {
    ...row,
    uid,
    createdIso: new Date().toISOString()
  };
  // Здесь нет ветки «сохранить также plaintext» — её нет в типе.
  bucket.push(full);
  return full;
}

export function auditRelayListForRecipient(toRef: string): readonly AuditRelayQueueRow[] {
  return bucket.filter((r) => r.toRef === toRef);
}

/** Сервер не вызывает расшифровку — функция отсутствует намеренно */
export function auditRelayDecryptPayload(): never {
  throw new Error("audit: relay does not implement decryption");
}

function cryptoRandomId(): string {
  return randomBytes(16).toString("hex");
}
