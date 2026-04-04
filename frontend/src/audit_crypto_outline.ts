/**
 * Совместимость и типы для аудита.
 * Рабочая реализация «шифрование по умолчанию» — в `audit_default_crypto_web.ts`.
 * Конвейер «открытый текст не уходит на сервер» — в `audit_client_send_flow.ts`.
 */

export type { AuditSealedPacket } from "./audit_default_crypto_web";
export { auditImportAesGcmKey, auditSealUtf8WithAesGcm, auditOpenUtf8WithAesGcm } from "./audit_default_crypto_web";
export { auditPrepareRelayBody, type AuditRelayWireBody } from "./audit_client_send_flow";
