import {t,dateLocale} from './i18n.js';
export function overall(device) {
  if (device.stale || !device.snapshot) return 'unknown';
  if (device.alarms.some(a=>a.health==='critical')) return 'critical';
  if (device.alarms.some(a=>a.health==='warning')) return 'warning';
  if (device.snapshot.capabilities.some(c=>c.outcome!=='available')) return 'unknown';
  const states=device.snapshot.observations.filter(o=>o.key!=='collector' && !o.key.startsWith('coverage:'));
  if (!states.length || states.some(o=>o.health==='unknown')) return 'unknown';
  return 'ok';
}
export const labels={get ok(){return t('In Ordnung')},get warning(){return t('Warnung')},get critical(){return t('Kritisch')},get unknown(){return t('Nicht vollständig bewertbar')}};
export function timestamp(seconds) { return seconds ? new Date(seconds*1000).toLocaleString(dateLocale()) : t("Noch keine Abfrage"); }

export function primaryAlarms(device){return device.alarms.filter(a=>!a.covered_by?.length);}
export function summaryAlarms(device){return device.alarms.filter(a=>a.covered_by?.length);}
export function alarmConfirmation(alarm){return alarm.current_health==='unknown'?t("Gespeicherter Fehler · aktuell nicht bewertbar"):alarm.current_health?t("Aktuell bestätigt"):t("Gespeicherter Fehler");}
export function coveredLabels(alarm,device){return (alarm.covered_by??[]).map(key=>device.alarms.find(a=>a.key===key)?.label??key).join(', ');}
