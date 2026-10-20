import {t} from './i18n.js';
export function replayPreviewOperation(event, recipient, recipients) {
  if(!Number.isSafeInteger(event?.id)||event.id<=0||!recipients.includes(recipient))throw new Error(t('Bitte ein Ereignis und einen gespeicherten Empfänger auswählen.'));
  return {action:'mail_replay_preview',event_id:event.id,recipient};
}
export function replaySendOperation(preview, event, recipient) {
  if(!/^[a-f0-9]{32}$/.test(preview?.id??'')||preview.event_id!==event?.id||preview.recipient!==recipient)throw new Error(t('Bitte zuerst eine aktuelle Versandvorschau erstellen.'));
  return {action:'mail_replay_send',id:preview.id};
}
export function replayStatus(job) {
  if(job.state==='submitted')return t('Vom SMTP-Server angenommen');
  if(job.state==='failed')return t('Versand fehlgeschlagen');
  if(job.state==='cancelled')return t('Versand storniert');
  return job.error?t('Erneuter Versuch vorgemerkt'):t('Zum Versand vorgemerkt');
}
export function replayError(code) {
  const messages={
    mail_conflict:'E-Mail-Einstellungen geändert',
    mail_timeout:'Keine rechtzeitige SMTP-Bestätigung. Die Mail könnte bereits angenommen worden sein; vor Wiederholung das Postfach prüfen.',
    mail_rejected:'Der SMTP-Server hat Anmeldung oder Nachricht dauerhaft abgewiesen. Zugang, Absender und Empfänger prüfen.',
    mail_connection_failed:'SMTP-Verbindung fehlgeschlagen. Server, Port, TLS-Zertifikat und Zugang prüfen.',
    mail_config_invalid:'SMTP-Angaben prüfen: Servername ohne URL, gültige Adressen, Port, TLS und Vorlagen sind erforderlich.',
    mail_template_invalid:'Die Vorlage enthält einen unbekannten oder unvollständigen Platzhalter.',
  };
  return code?t(messages[code]??'Versand fehlgeschlagen'):'';
}
