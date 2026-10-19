import {t,dateLocale} from './i18n.js';
export function eventCategory(event) {
  if(event.kind==='hardware_log')return 'log';
  if(event.key==='collector'||event.key?.startsWith('coverage:'))return 'monitoring';
  return 'hardware';
}
export function eventType(event) {
  const category=eventCategory(event);
  if(category==='log')return t("Hardwarelog");
  if(event.kind==='recovery')return category==='monitoring'?t("Abfrage wieder erfolgreich"):t("Hardware-Entwarnung");
  if(event.kind==='repeat')return category==='monitoring'?t("Abfrage weiterhin gestört"):t("Alarmwiederholung");
  return category==='monitoring'?t("Abfragewarnung"):t("Hardwarealarm");
}
export function emailDeliveryText(event) {
  if(event.mail_reason==='aggregate')return t("Sammelmeldung gebündelt · {0}",event.submitted_recipients?t("{0} bereits per SMTP angenommen",event.submitted_recipients):t("keine zusätzliche E-Mail"));
  if(event.transport==='smtp') {
    const progress=`${event.submitted_recipients??0}/${event.total_recipients??0}`;
    if(event.delivered)return t("Vom SMTP-Server angenommen · {0}",progress);
    if(event.cancelled)return t("Versand storniert · {0} angenommen",progress);
    if(event.failed_recipients)return t("Versandfehler · {0} angenommen",progress);
    if(event.delivery_error)return t("Erneuter Versuch vorgemerkt · {0} angenommen",progress);
    return t("E-Mail vorgemerkt · {0} angenommen",progress);
  }
  const reason={device_disabled:t("am Gerät deaktiviert"),monitoring_disabled:t("Überwachung deaktiviert"),filtered:t("durch Ereignisauswahl ausgeschlossen"),mail_disabled:t("automatischer Versand deaktiviert"),mail_not_configured:t("SMTP nicht eingerichtet")}[event.mail_reason];
  if(reason)return t("E-Mail: {0}",reason);
  if(event.delivered)return t("An DSM übergeben");
  if(event.cancelled)return t("Vormerkung storniert");
  if(event.queued)return t("Lokal vorgemerkt · kein Versand aktiv");
  return t("Lokal gespeichert");
}
export function deliveryText(event) {
  const email=emailDeliveryText(event),desktop=event.desktop;
  if(event.desktop_reason==='aggregate')return t("{0} · DSM-Desktop: Sammelmeldung gebündelt",email);
  if(desktop){
    const state=desktop.delivered?t("an DSM übergeben"):desktop.cancelled?t('storniert'):desktop.attempts>=8?t("Versandfehler"):desktop.error?t("erneuter Versuch vorgemerkt"):t('vorgemerkt');
    return t("{0} · DSM-Desktop: {1}",email,state);
  }
  if(event.desktop_reason==='filtered')return t("{0} · DSM-Desktop: durch Ereignisauswahl ausgeschlossen",email);
  if(event.desktop_reason==='desktop_disabled')return t("{0} · DSM-Desktop: deaktiviert",email);
  return email;
}
export function filterEvents(events,filter) {
  return events.filter(e=>(filter.category==='all'||eventCategory(e)===filter.category)&&(filter.health==='all'||e.health===filter.health)&&(filter.device==='all'||e.device===filter.device));
}
export function sourceTimestamp(value) {
  if(typeof value!=='string')return '';
  const parsed=Date.parse(value);return Number.isFinite(parsed)?new Date(parsed).toLocaleString(dateLocale()):'';
}
export function capabilityText(c) {
  if(c.outcome==='available')return c.attempts>1?t("Erfolgreich nach Wiederholung"):t("Erfolgreich");
  if(c.http_status)return `HTTP ${c.http_status}${c.attempts>1?t(" · {0} Versuche",c.attempts):''}`;
  const failure={deadline:"Zeitlimit der vollständigen Abfrage erreicht",resource_limit:"Ressourcenlimit der Abfrage erreicht",byte_limit:"Datenmengenlimit der Abfrage erreicht",item_limit:"Messwert- oder Hardwareloglimit erreicht",response_limit:"Antwort überschreitet das Größenlimit",invalid_response:"Ungültige Redfish-Antwort",certificate_error:"Serverzertifikat stimmt nicht überein oder ist zeitlich ungültig",timeout:"Zeitlimit der Teilabfrage erreicht",unsafe_link:"Unsicherer Redfish-Verweis abgewiesen",tls_error:"TLS-Verbindung fehlgeschlagen"}[c.outcome];
  if(failure)return t(failure);
  return ({forbidden_permission_or_license:t("Zugriff verweigert · Berechtigung oder Lizenz prüfen"),not_found:t("Nicht gefunden"),transport_error:t("Netzwerk- oder TLS-Fehler"),http_error:t("HTTP-Fehler · Status im alten Datensatz nicht gespeichert")})[c.outcome]??t("Nicht vollständig abgefragt");
}
// Preserve the DB history. Only combine identical transitions from distinct,
// positively correlated API representations; repeated rows from one source stay.
export function groupEvents(events) {
  const groups=[],buckets=new Map();
  for(const event of events) {
    const copy={...event,source_keys:[event.key],merged_count:1};
    if(event.kind==='hardware_log'||!event.canonical_key){groups.push(copy);continue;}
    const key=JSON.stringify([event.device,event.canonical_key,event.kind,event.health,event.created,event.message]);
    const bucket=buckets.get(key)??[];
    const existing=bucket.find(group=>!group.source_keys.includes(event.key));
    if(existing){
      const active=(existing.queued&&!existing.cancelled)||(event.queued&&!event.cancelled);
      existing.delivered=existing.delivered||event.delivered;
      existing.queued=existing.queued||event.queued;
      existing.cancelled=Boolean(existing.queued&&!active&&!existing.delivered);
      existing.source_keys.push(event.key);existing.merged_count++;
    }
    else{bucket.push(copy);groups.push(copy);}
    buckets.set(key,bucket);
  }
  return groups;
}
