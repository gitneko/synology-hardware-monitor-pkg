import {t,dateLocale} from './i18n.js';
export function measurementSnapshot(device) {
  const snapshot=device?.snapshot;
  return Array.isArray(snapshot?.observations) && Array.isArray(snapshot?.capabilities) ? snapshot : null;
}
export function overall(device) {
  if (device.stale || !measurementSnapshot(device)) return 'unknown';
  if (['ok','warning','critical','unknown','acknowledged'].includes(device.overall_status)) return device.overall_status;
  if (device.alarms.some(a=>a.health==='critical')) return 'critical';
  if (device.alarms.some(a=>a.health==='warning')) return 'warning';
  if (device.snapshot.capabilities.some(c=>c.outcome!=='available')) return 'unknown';
  const states=device.snapshot.observations.filter(o=>o.key!=='collector' && !o.key.startsWith('coverage:') && !assessmentReason(o,device.snapshot));
  if (states.some(o=>o.health==='critical')) return 'critical';
  if (states.some(o=>o.health==='warning')) return 'warning';
  if (!states.length || states.some(o=>o.health==='unknown')) return 'unknown';
  return 'ok';
}
export const labels={get acknowledged(){return t('Bestätigt')},get ok(){return t('In Ordnung')},get warning(){return t('Warnung')},get critical(){return t('Kritisch')},get unknown(){return t('Nicht vollständig bewertbar')}};
export function assessmentReason(observation,snapshot) {
  if (observation.health!=='unknown') return '';
  switch(snapshot?.assessment_exclusions?.[observation.key]) {
    case 'disabled':return t('Deaktiviert');
    case 'absent':return t('Vom Gerät als nicht vorhanden gemeldet');
    case 'empty_controller':return t('Keine Laufwerke oder Volumes vorhanden');
    case 'informational':return t('Reiner Messwert ohne Zustandsmeldung');
    default:return '';
  }
}
export function observationStatus(observation,snapshot,device) {return device?.alarm_statuses?.[observation.key]?.status??( assessmentReason(observation,snapshot)?'not_applicable':observation.health);}
export function observationLabel(observation,snapshot,device) {
  const status=observationStatus(observation,snapshot,device);
  if(status!=='not_applicable')return labels[status];
  return ({absent:t('Nicht vorhanden'),disabled:t('Deaktiviert'),informational:t('Information'),empty_controller:t('Controller ohne Laufwerke')})[snapshot.assessment_exclusions[observation.key]]??t('Nicht relevant');
}
export function timestamp(seconds) { return seconds ? new Date(seconds*1000).toLocaleString(dateLocale()) : t("Noch keine Abfrage"); }

export function primaryAlarms(device,filter='all'){return device.alarms.filter(a=>!a.covered_by?.length && matchesAlarm(a,filter));}
export function summaryAlarms(device,filter='all'){return device.alarms.filter(a=>a.covered_by?.length && matchesAlarm(a,filter));}
function matchesAlarm(alarm,filter){return filter==='all'||(filter==='acknowledged')===(alarm.assessment?.status==='acknowledged');}
export function alarmConfirmation(alarm){return alarm.current_health==='unknown'?t("Gespeicherter Fehler · aktuell nicht bewertbar"):alarm.current_health?t("Aktuell gemessen"):t("Gespeicherter Fehler");}
export function coveredLabels(alarm,device){return (alarm.covered_by??[]).map(key=>device.alarms.find(a=>a.key===key)?.label??key).join(', ');}
