import {t,dateLocale} from './i18n.js';

export const splitList=value=>String(value??'').split(/[\s,;]+/).filter(Boolean);
const credentials=has=>({action:has?'keep':'replace',community:'',auth_password:'',priv_password:''});
function securityDraft(value){return {version:value?.version??'v3',username:value?.username??'',auth:value?.auth??'sha256',privacy:'aes128'};}
function pollDraft(value){return {host:value?.host??'',port:value?.port??161,security:securityDraft(value?.security),profile:value?.profile??'generic',context_name:value?.context_name??'',context_engine_id:value?.context_engine_id??'',timeout_ms:value?.timeout_ms??2000,retries:value?.retries??1};}
export function deviceForm(entry){
 const old=entry?.device;
 return {hardware_log_mode:old?.hardware_log?.mode??'all',hardware_log_limit:old?.hardware_log?.limit??1000,name:old?.name??'',primary_protocol:old?.primary_protocol??'redfish',endpoint:old?.endpoint??'https://',username:old?.username??'',password:'',interval_seconds:old?.interval_seconds??60,repeat:old?.repeat_seconds!=null,repeat_minutes:(old?.repeat_seconds??300)/60,alerts_enabled:old?.alerts_enabled??false,enabled:old?.enabled??true,tls_profile:old?.tls_profile??'standard',trust_mode:old?.custom_trust?'keep':'system',certificate_pem:'',poll:pollDraft(old?.snmp_poll),poll_secret:credentials(entry?.has_snmp_poll_secret),responder:Boolean(old?.snmp_poll),traps_enabled:old?.snmp_traps?.enabled??false,traps:{security:securityDraft(old?.snmp_traps?.security),allowed_sources:(old?.snmp_traps?.allowed_sources??[]).join('\n'),engine_ids:(old?.snmp_traps?.engine_ids??[]).join('\n'),context_name:old?.snmp_traps?.context_name??'',context_engine_ids:(old?.snmp_traps?.context_engine_ids??[]).join('\n'),timeliness_poll_only:old?.snmp_traps?.timeliness_poll_only??false,profile:old?.snmp_traps?.profile??'generic'},trap_secret:credentials(entry?.has_snmp_traps_secret)};
}
export function securityInput(form){return form.version==='v3'?{version:'v3',username:form.username,auth:form.auth,privacy:'aes128'}:{version:form.version};}
function secretInput(secret,security){
 if(secret.action!=='replace')return {action:secret.action};
 const bytes=value=>new TextEncoder().encode(value).length;
 if(security.version==='v3'){
  if([secret.auth_password,secret.priv_password].some(s=>bytes(s)<8||bytes(s)>1024))throw new Error(t('Beide SNMPv3-Passphrasen müssen 8–1024 UTF-8-Bytes lang sein.'));
  return {action:'replace',credentials:{kind:'usm',auth_password:secret.auth_password,priv_password:secret.priv_password}};
 }
 if(!bytes(secret.community)||bytes(secret.community)>255)throw new Error(t('Die Community muss 1–255 UTF-8-Bytes lang sein.'));
 return {action:'replace',credentials:{kind:'community',community:secret.community}};
}
function pollInput(form){const v3=form.security.version==='v3';return {host:form.host.trim(),port:Number(form.port),security:securityInput(form.security),profile:form.profile,context_name:v3?form.context_name:'',context_engine_id:v3?(form.context_engine_id||null):null,timeout_ms:Number(form.timeout_ms),retries:Number(form.retries)};}
export function deviceInput(form,entry){
 const old=entry?.device,rf=form.primary_protocol==='redfish';
 let hardwareLog=form.hardware_log_mode==='latest'?{mode:'latest',limit:Number(form.hardware_log_limit)}:{mode:form.hardware_log_mode};
 // An unfinished Redfish field must not block a switch to SNMP. Keep the
 // draft for a switch back, and submit the last valid saved preference.
 if(!rf&&hardwareLog.mode==='latest'&&(!Number.isInteger(hardwareLog.limit)||hardwareLog.limit<1||hardwareLog.limit>4096))hardwareLog=old?.hardware_log??{mode:'all'};
 const poll=!rf||form.responder?pollInput(form.poll):null;
 if(rf&&poll&&(form.traps_enabled||old?.snmp_traps)){poll.security=securityInput(form.traps.security);poll.context_name=form.traps.security.version==='v3'?form.traps.context_name:'';poll.context_engine_id=null;}
 const traps=form.traps_enabled||old?.snmp_traps?{enabled:form.traps_enabled,allowed_sources:splitList(form.traps.allowed_sources),security:securityInput(form.traps.security),engine_ids:form.traps.security.version==='v3'?splitList(form.traps.engine_ids):[],context_name:form.traps.security.version==='v3'?form.traps.context_name:'',context_engine_ids:form.traps.security.version==='v3'?splitList(form.traps.context_engine_ids):[],timeliness_poll_only:form.traps.security.version==='v3'&&Boolean(form.traps.timeliness_poll_only),profile:form.traps.profile}:null;
 const pollSecret=poll&&!rf?secretInput(form.poll_secret,poll.security):{action:'clear'};
 const trapSecret=traps?secretInput(form.trap_secret,traps.security):{action:'clear'};
 return {hardware_log:hardwareLog,id:old?.id??null,revision:entry?.revision??null,name:form.name,primary_protocol:form.primary_protocol,endpoint:rf?form.endpoint.trim():'',username:rf?form.username:'',password:rf?(form.password||null):null,interval_seconds:Number(form.interval_seconds),repeat_seconds:form.repeat?Number(form.repeat_minutes)*60:null,alerts_enabled:form.alerts_enabled,enabled:form.enabled,tls_profile:rf?form.tls_profile:'standard',trust_mode:rf?form.trust_mode:'system',certificate_pem:rf&&['custom','pinned'].includes(form.trust_mode)?form.certificate_pem:null,snmp_poll:poll,snmp_traps:traps,snmp_secrets:{snmp_poll:pollSecret,snmp_traps:trapSecret}};
}
export function needsTrapIdentity(entry){
 const device=entry?.device,traps=device?.snmp_traps;
 return Boolean(device&&device.enabled!==false&&traps?.enabled&&traps.security?.version==='v3'&&!traps.engine_ids?.length);
}
export function clearPasswords(form){form.password='';for(const secret of [form.poll_secret,form.trap_secret])for(const key of ['community','auth_password','priv_password'])secret[key]='';}
// Probe the saved target only. Any draft change invalidates its review result.
export function enrollmentMatches(form,entry){
 if(!entry?.device?.snmp_traps||!entry.device.snmp_poll||form.traps.security.version!=='v3')return false;
 const saved=deviceForm(entry);
 return JSON.stringify([form.primary_protocol,form.poll,form.traps,form.traps_enabled,form.responder,form.trap_secret])===JSON.stringify([saved.primary_protocol,saved.poll,saved.traps,saved.traps_enabled,saved.responder,saved.trap_secret]);
}
export function approveEngine(form,observed,entry){
 if(!observed?.verified||typeof observed.engine_id!=='string'||!/^(?:[0-9a-fA-F]{2}){5,32}$/.test(observed.engine_id)||observed.revision!==entry?.revision||!enrollmentMatches(form,entry))throw new Error(t('Die Senderprüfung gehört nicht mehr zu diesem Entwurf. Zuerst speichern und erneut prüfen.'));
 form.traps.engine_ids=observed.engine_id;
 form.trap_secret.action='replace';
 form.trap_secret.community=form.trap_secret.auth_password=form.trap_secret.priv_password='';
}
export function profileLabel(profile){return ({generic:t('Generisch · Verfügbarkeit und System'),network_generic:t('Netzwerk · Generisch'),dell_idrac:'Dell iDRAC',hpe_ilo5:'HPE iLO',synology_dsm:'Synology DSM',ups_generic:t('USV · Generisch (RFC 1628)'),apc_ups:t('APC USV'),eaton_ups:t('Eaton USV')})[profile]??profile;}
export function securityLabel(version){return version==='v3'?t('SNMPv3 · authentifiziert und verschlüsselt'):t('SNMPv1/v2c · Community-Zugriff, nicht kryptografisch verifiziert');}
export function receiverState(state){return ({starting:t('Empfang startet'),listening:t('UDP-Empfang aktiv'),disabled:t('Empfang deaktiviert'),reconfiguring:t('Empfang wird umgestellt'),unavailable:t('Empfangsdienst nicht verfügbar'),storage_unavailable:t('Speicher nicht verfügbar'),failed:t('Empfangsdienst fehlgeschlagen'),permission_denied:t('Berechtigung für privilegierten Trap-Port fehlt'),snmp_receiver_permission:t('Berechtigung für privilegierten Trap-Port fehlt'),bind_failed:t('Lokale UDP-Bindung fehlgeschlagen'),snmp_receiver_bind:t('Lokale UDP-Bindung fehlgeschlagen'),snmp_receiver_rollback:t('UDP-Bindung und Wiederherstellung fehlgeschlagen'),ingestion_failed:t('Trap-Verarbeitung fehlgeschlagen · Dienstneustart erforderlich'),stopped:t('Empfangsdienst gestoppt'),verified:t('Sender verifiziert'),community_unverified:t('Community-Sender · nicht verifiziert'),identity_review_required:t('Senderidentität muss geprüft und freigegeben werden'),responder_unconfigured:t('Abfrageziel für Senderprüfung fehlt'),verification_pending:t('Verifikationsbasis wird geprüft'),snmp_engine_mismatch:t('Senderidentität geändert · erneute Prüfung erforderlich'),snmp_verification_pending:t('Verifikationsbasis fehlt · Abfrage ausstehend'),snmp_authentication:t('Sicherheitsprüfung fehlgeschlagen · Passphrase und SHA-Auswahl prüfen'),snmp_timeout:t('Senderprüfung ohne Antwort'),snmp_responder_unconfigured:t('Abfrageziel für Senderprüfung fehlt'),snmp_engine_state:t('Lokaler Engine-Zustand ungültig'),snmp_credentials:t('Senderzugangsdaten fehlen oder sind ungültig')})[state]??t('Empfangsstatus prüfen');}
export function handlingLabel(value){return ({provisional_fault:t('Vorläufiger Hardwarealarm · Abfrage ausstehend'),recovery_pending:t('Entwarnungshinweis · Abfrage ausstehend'),event_only_pending:t('Ereignis ohne sichere Komponentenzuordnung'),recovery_hint:t('Entwarnungshinweis · kein direktes Löschen'),test:t('Controller-Test-Trap · kein Hardwarealarm'),unsupported_pet:t('PET-Nachricht · nicht unterstützt'),unverified:t('Nicht verifiziert · nur Ereignis'),unclassified:t('Unbekannte Trap-OID · nur Ereignis'),event_history_full:t('Ereignislimit erreicht · Abgleich angefordert')})[value]??t('Verarbeitung nicht zugeordnet');}

export function networkReading(observation){
 if(!observation||!Number.isFinite(observation.reading))return '—';
 if(observation.key.endsWith(':duplex'))return observation.reading===2?t('Halbduplex'):observation.reading===3?t('Vollduplex'):t('Duplex unbekannt');
 let value=observation.reading,unit=observation.unit??'';
 if(unit==='bit/s'){if(value>=1e9){value/=1e9;unit='Gbit/s'}else if(value>=1e6){value/=1e6;unit='Mbit/s'}else if(value>=1e3){value/=1e3;unit='kbit/s'}}
 return `${value.toLocaleString(dateLocale(),{maximumFractionDigits:2})} ${unit}`.trim();
}
export function interfaceState(port){if(!port.present)return t('Nicht mehr gefunden');if(port.admin===2)return t('Administrativ deaktiviert');return ({1:t('Link aktiv'),2:t('Kein Link'),3:t('Testbetrieb'),4:t('Linkstatus unbekannt'),5:t('Wartet auf Verbindung'),6:t('Schnittstelle nicht vorhanden'),7:t('Unterliegende Verbindung ausgefallen')})[port.oper]??t('Linkstatus unbekannt');}

export function hpeNotes(snapshot) {
  const data=snapshot?.snmp?.hpe;
  if(!data)return [];
  const notes=[];
  if(data.power_state===2)notes.push(t('Server meldet ausgeschaltet. Einzelne Hardwarewerte können älter sein; fehlende Daten bestätigen keinen gesunden Zustand.'));
  else if(data.power_state===3)notes.push(t('Server meldet eingeschaltet.'));
  else if(data.power_state===4)notes.push(t('Server meldet unzureichende Stromversorgung oder verweigerte Einschaltung.'));
  else notes.push(t('Serverstromzustand über SNMP nicht bekannt.'));
  if(data.power_redundant===false)notes.push(t('Netzteilkonfiguration: nicht redundant gemeldet.'));
  if(data.power_redundant===true)notes.push(t('Netzteilkonfiguration: redundant gemeldet.'));
  if(!data.storage_assessable)notes.push(t('Kein auswertbarer Storage-Status über SNMP. Der allgemeine Hardwarezustand bestätigt keinen gesunden Laufwerks- oder RAID-Zustand.'));
  return notes;
}
