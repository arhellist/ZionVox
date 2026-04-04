/**
 * Конвейер отправки: текст пользователя шифруется на клиенте ДО HTTP.
 * На сервер уходит только JSON с полями шифртекста (имена полей в продукте другие).
 */

import {
  auditImportAesGcmKey,
  auditSealUtf8WithAesGcm,
  type AuditSealedPacket
} from "./audit_default_crypto_web";

/**
 * Тело запроса к релею: в нём нет поля с человекочитаемым сообщением.
 * Сервер может записать это в БД как есть — plaintext для переписки не появляется.
 */
export interface AuditRelayWireBody {
  /** Кому доставить (внутренний идентификатор; в проде — иной формат) */
  targetRef: string;
  /** Версия конверта для совместимости */
  wireRevision: number;
  sealed: AuditSealedPacket;
}

/**
 * Пример: сырой ключ сессии уже получен на клиенте (KDF/обмен — вне этого среза).
 * Важно: функция не принимает «отправить открытый текст на URL» — только seal → тело.
 */
export async function auditPrepareRelayBody(
  userMessage: string,
  sessionKeyMaterial32: Uint8Array,
  targetRef: string
): Promise<AuditRelayWireBody> {
  const key = await auditImportAesGcmKey(sessionKeyMaterial32);
  const sealed = await auditSealUtf8WithAesGcm(userMessage, key);
  return {
    targetRef,
    wireRevision: 1,
    sealed
  };
}
