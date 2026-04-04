/**
 * Схема хранения на стороне релея (аудит).
 *
 * Инвариант: в типе записи НЕТ поля для текста сообщения в открытом виде.
 * Если бы оно появилось — это было бы нарушением заявленной модели.
 */

/** Одна запись очереди доставки — только непрозрачные полезные нагрузки */
export interface AuditRelayQueueRow {
  uid: string;
  /** Кто отправил (внутренний ref, не email) */
  fromRef: string;
  /** Кому адресовано */
  toRef: string;
  /** Шифртекст + IV в JSON или отдельных колонках — для сервера это blob */
  payloadCipherB64: string;
  ivB64: string;
  createdIso: string;
}

/** Явный список полей, которые разрешено сохранять — без plaintext */
export const AUDIT_RELAY_PERSISTED_FIELDS = [
  "uid",
  "fromRef",
  "toRef",
  "payloadCipherB64",
  "ivB64",
  "createdIso"
] as const;

export type AuditRelayPersistedField = (typeof AUDIT_RELAY_PERSISTED_FIELDS)[number];
