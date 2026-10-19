import {t,dateLocale} from './i18n.js';
export function measurementSnapshot(device) {
  const snapshot=device?.snapshot;
  return Array.isArray(snapshot?.observations) && Array.isArray(snapshot?.capabilities) ? snapshot : null;
}
export function overall(device) {
  if (device.stale || !measurementSnapshot(device)) return 'unknown';
  if (device.alarms.some(a=>a.health==='critical')) return 'critical';
  if (device.alarms.some(a=>a.health==='warning')) return 'warning';
  if (device.snapshot.capabilities.some(c=>c.outcome!=='available')) return 'unknown';
  const states=device.snapshot.observations.filter(o=>o.key!=='collector' && !o.key.startsWith('coverage:') && !assessmentReason(o,device.snapshot));
  if (states.some(o=>o.health==='critical')) return 'critical';
  if (states.some(o=>o.health==='warning')) return 'warning';
  if (!states.length || states.some(o=>o.health==='unknown')) return 'unknown';
  return 'ok';
}
export const labels={get ok(){return t('In Ordnung')},get warning(){return t('Warnung')},get critical(){return t('Kritisch')},get unknown(){return t('Nicht vollständig bewertbar')}};
export function assessmentReason(observation,snapshot) {
  if (observation.health!=='unknown') return '';
  switch(snapshot?.assessment_exclusions?.[observation.key]) {
    case 'disabled':return t('Deaktiviert');
    case 'empty_controller':return t('Keine Laufwerke oder Volumes vorhanden');
    case 'informational':return t('Reiner Messwert ohne Zustandsmeldung');
    default:return '';
  }
}
export function observationStatus(observation,snapshot) {return assessmentReason(observation,snapshot)?'not_applicable':observation.health;}
export function observationLabel(observation,snapshot) {return assessmentReason(observation,snapshot)?t('Nicht relevant'):labels[observation.health];}
export function timestamp(seconds) { return seconds ? new Date(seconds*1000).toLocaleString(dateLocale()) : t("Noch keine Abfrage"); }

export function primaryAlarms(device){return device.alarms.filter(a=>!a.covered_by?.length);}
export function summaryAlarms(device){return device.alarms.filter(a=>a.covered_by?.length);}
export function alarmConfirmation(alarm){return alarm.current_health==='unknown'?t("Gespeicherter Fehler · aktuell nicht bewertbar"):alarm.current_health?t("Aktuell bestätigt"):t("Gespeicherter Fehler");}
export function coveredLabels(alarm,device){return (alarm.covered_by??[]).map(key=>device.alarms.find(a=>a.key===key)?.label??key).join(', ');}
