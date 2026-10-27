<script setup>
import {t} from './i18n.js';
import {ref,reactive,watch,onMounted,onUnmounted} from 'vue';
import {administer} from './device-api.js';
import {deviceForm,deviceInput,clearPasswords,enrollmentMatches,approveEngine,profileLabel,securityLabel} from './snmp.js';
import SnmpSecurity from './SnmpSecurity.vue';
import SnmpPollFields from './SnmpPollFields.vue';
import {capabilityText} from './events.js';
const props=defineProps({entry:Object,dashboard:Object,verifySender:Boolean});
const emit=defineEmits(['close','saved']);
const old=props.entry?.device;
const form=reactive(deviceForm(props.entry));
const busy=ref(false),error=ref(''),result=ref(null),confirmDelete=ref(false),nameField=ref(null),formElement=ref(null),identity=ref(null),probing=ref(false),probeButton=ref(null);
watch(()=>form.tls_profile,()=>{form.trust_mode=form.tls_profile==='idrac7'?'pinned':'system';form.certificate_pem='';});
watch(form,()=>{result.value=null;error.value='';confirmDelete.value=false;identity.value=null;});
let controller;
const previousFocus=document.activeElement;
onMounted(()=>{if(props.verifySender&&enrollmentMatches(form,props.entry)){probeButton.value?.focus();run('snmp_trap_probe');}else nameField.value?.focus();});
onUnmounted(()=>{controller?.abort();clearPasswords(form);previousFocus?.focus();});
function close(){if(!busy.value){clearPasswords(form);emit('close');}}
function input(){return deviceInput(form,props.entry);}
async function run(action){
  if(busy.value)return;
  if(!['delete','snmp_trap_probe'].includes(action)&&!formElement.value.reportValidity())return;
  busy.value=true;probing.value=action==='snmp_trap_probe';error.value='';result.value=null;controller=new AbortController();
  const timeout=setTimeout(()=>controller.abort(),25000);
  try{
    const operation=['delete','snmp_trap_probe'].includes(action)?{action,id:old.id,revision:props.entry.revision}:{action,device:input()};
    const body=await administer(props.dashboard,operation,fetch,controller.signal);
    if(action==='test')result.value=body.connection;
    else if(action==='snmp_trap_probe')identity.value=body;
    else{clearPasswords(form);emit('saved',body.id??null);}
  }catch(e){error.value=e.name==='AbortError'?t("Zeitüberschreitung. Bitte aktualisieren und das Ergebnis prüfen."):e.message;}
  finally{clearTimeout(timeout);busy.value=false;probing.value=false;}
}
async function importCertificate(event){
  error.value='';const file=event.target.files?.[0];
  if(!file)return;
  if(file.size>65536){error.value=t("Die Zertifikatsdatei darf höchstens 64 KiB groß sein.");event.target.value='';return;}
  form.certificate_pem=await file.text();form.trust_mode=form.tls_profile==='idrac7'?'pinned':'custom';
}
function trap(event){
  if(event.key==='Escape'){close();return;}
  if(event.key!=='Tab')return;
  const controls=[...event.currentTarget.querySelectorAll('input,select,textarea,button')].filter(el=>!el.disabled && el.offsetParent!==null);
  const first=controls[0],last=controls.at(-1);
  if(event.shiftKey && document.activeElement===first){event.preventDefault();last?.focus();}
  else if(!event.shiftKey && document.activeElement===last){event.preventDefault();first?.focus();}
}
</script>
<template>
<div class="modal-backdrop"><section class="device-editor" role="dialog" aria-modal="true" aria-labelledby="editor-title" @keydown="trap">
  <header><div><p class="eyebrow">{{t("GERÄTEVERWALTUNG")}}</p><h2 id="editor-title">{{old?t("Gerät bearbeiten"):t("Gerät hinzufügen")}}</h2></div><button type="button" class="refresh" :disabled="busy" :aria-label="t(&quot;Schließen&quot;)" @click="close">×</button></header>
  <form ref="formElement" @submit.prevent="run('save')">
    <fieldset :disabled="busy"><legend class="sr-only">{{t("Geräteangaben")}}</legend>
      <label>Name<input ref="nameField" v-model="form.name" required maxlength="160" :placeholder="t(&quot;Zum Beispiel: Dell R340&quot;)" autocomplete="off"></label>
      <label>{{t('Primäres Abfrageprotokoll')}}<select v-model="form.primary_protocol"><option value="redfish">Redfish (HTTPS)</option><option value="snmp">SNMP</option></select></label>
      <SnmpPollFields v-if="form.primary_protocol==='snmp'" :poll="form.poll" :secret="form.poll_secret" :has-secret="entry?.has_snmp_poll_secret" :required-secret="form.enabled"/>
      <template v-else>
      <label>{{t("HTTPS-Adresse")}}<input v-model="form.endpoint" type="url" required placeholder="https://idrac.example.local/" autocomplete="off"><small>{{t("Die Management-Adresse ohne Redfish-Pfad. HTTPS-Zertifikate werden immer geprüft.")}}</small></label>
      <div class="form-columns"><label>{{t("Gerätebenutzer")}}<input v-model="form.username" required maxlength="128" autocomplete="off"></label><label>{{old?t("Passwort ersetzen (optional)"):t("Gerätepasswort")}}<input v-model="form.password" type="password" :required="!old" maxlength="4096" autocomplete="new-password"><small v-if="old">{{t("Leer lassen, um es zu behalten. Bei neuer Adresse oder neuem Benutzer ist ein Passwort erforderlich.")}}</small></label></div>
      <label>{{t("Verbindungsmodus")}}<select v-model="form.tls_profile"><option value="standard">{{t("Standard")}}</option><option value="idrac7">{{t("Kompatibilität mit iDRAC7/8 und iLO")}}</option></select></label>
      <label>{{t("Zertifikatsvertrauen")}}<select v-model="form.trust_mode"><option v-if="old?.custom_trust && form.tls_profile===(old?.tls_profile??'standard')" value="keep">{{t("Gespeichertes Zertifikat beibehalten")}}</option><template v-if="form.tls_profile==='standard'"><option value="system">{{t("Öffentlich vertrauenswürdiges Zertifikat")}}</option><option value="custom">{{t("Eigene CA oder Serverzertifikat importieren")}}</option></template><option v-else value="pinned">{{t("Genau diesem Serverzertifikat vertrauen")}}</option></select></label>
      <p v-if="form.tls_profile==='idrac7'" class="form-note">{{t("Importiere das Serverzertifikat des Controllers aus einer vertrauenswürdigen Quelle. Nur dieses Zertifikat wird akzeptiert; Name und CA-Kennzeichnung werden durch den exakten Zertifikatsvergleich ersetzt. Die zeitliche Gültigkeit wird weiterhin geprüft. Bei Zertifikatswechsel erneut importieren.")}}</p>
      <p v-if="form.tls_profile==='idrac7'" class="form-note">{{t("Bei älteren iDRAC-Controllern darf eine vollständige Abfrage bis zu fünf Minuten dauern. Die eingestellte Pause beginnt nach Abschluss der vorherigen Abfrage.")}}</p>
      <p v-if="form.trust_mode==='keep' && old?.certificate_fingerprint" class="form-note">{{t("Zertifikat SHA-256:")}} <code>{{old.certificate_fingerprint}}</code></p>
      <div v-if="['custom','pinned'].includes(form.trust_mode)" class="certificate-input"><label>{{t("Zertifikatsdatei (PEM)")}}<input type="file" accept=".pem,.crt,.cer" @change="importCertificate"></label><label>{{t("PEM-Zertifikat")}}<textarea v-model="form.certificate_pem" rows="4" required spellcheck="false" placeholder="-----BEGIN CERTIFICATE-----"></textarea></label><small>{{form.tls_profile==='idrac7'?t("Ein einzelnes Serverzertifikat, kein privater Schlüssel."):t("Nur Zertifikate, keine privaten Schlüssel. Der Hostname muss weiterhin zum Zertifikat passen.")}}</small></div>
      </template>
      <h3>{{t('SNMP-Trap-Empfang für dieses Gerät')}}</h3>
      <label class="check"><input v-model="form.traps_enabled" type="checkbox">{{t('SNMP-Traps empfangen')}}</label>
      <template v-if="form.traps_enabled || old?.snmp_traps">
      <p class="form-note">{{t('Zusätzlich muss der globale SNMP-Empfänger aktiviert sein. Traps ersetzen keine reguläre Hardwareabfrage; eine Entwarnung wird durch die nächste vollständige Abfrage bestätigt.')}}</p>
      <SnmpSecurity :security="form.traps.security" :secret="form.trap_secret" :has-secret="entry?.has_snmp_traps_secret" :required-secret="form.enabled && form.traps_enabled"/>
      <label>{{t('Erlaubte Absender-IP-Adressen')}}<textarea v-model="form.traps.allowed_sources" :required="form.traps_enabled" rows="2" spellcheck="false" placeholder="192.0.2.10&#10;2001:db8::10"></textarea><small>{{t('Bis zu 16 einzelne IPv4-/IPv6-Adressen, getrennt durch Zeilen oder Kommas. Keine Hostnamen oder Netzbereiche.')}}</small></label>
      <label>{{t('Trap-Hardwareprofil')}}<select v-model="form.traps.profile"><option value="generic">{{t('Generisch · Systemidentität')}}</option><option value="dell_idrac">Dell iDRAC</option><option value="hpe_ilo5">HPE iLO</option></select></label>
      <template v-if="form.traps.security.version==='v3'">
      <label class="check"><input v-model="form.traps.timeliness_poll_only" type="checkbox">{{t('Kompatibilität bei abweichendem Boots-Zähler oder Engine-Zeit')}}</label>
      <p class="form-note">{{t('Für Controller mit inkonsistenter SNMPv3-Zeitbasis, z. B. nach einem Neustart. Korrekt signierte und entschlüsselte Traps außerhalb des Zeitfensters lösen nur eine beschleunigte Geräteabfrage aus. Alarme und Benachrichtigungen entstehen aus dem Abfrageergebnis. Diese Traps erzeugen keinen Empfangsbeleg und keinen direkten Trap-Alarm; ihre Aktualität ist nicht bestätigt. Normale zeitlich gültige Traps werden weiterhin regulär verarbeitet.')}}</p>
      <label>{{t('Freigegebene Sender-Engine-IDs (Hex)')}}<textarea v-model="form.traps.engine_ids" rows="2" spellcheck="false"></textarea><small>{{t('Nur geprüfte Identitäten freigeben. Ohne Freigabe bleibt der v3-Sender gesperrt. Eine geänderte Engine-ID benötigt eine neue Prüfung; erhöhte Boots-Zähler derselben Engine werden automatisch neu verifiziert.')}}</small></label>
      <div class="form-columns"><label>{{t('Trap-Kontextname filtern (optional)')}}<input v-model="form.traps.context_name" maxlength="32" autocomplete="off"><small>{{t('Leer: alle Kontextnamen des verifizierten Senders zulassen. Ein eingetragener Name muss genau übereinstimmen.')}}</small></label><label>{{t('Erlaubte Kontext-Engine-IDs (optional, Hex)')}}<textarea v-model="form.traps.context_engine_ids" rows="2" spellcheck="false"></textarea><small>{{t('Leer: keine zusätzliche Kontext-Engine-ID einschränken. Die freigegebene Sender-Engine-ID wird unabhängig davon geprüft.')}}</small></label></div>
      <template v-if="form.primary_protocol==='redfish'"><label class="check"><input v-model="form.responder" type="checkbox">{{t('SNMP-Abfrageziel für Senderprüfung hinterlegen')}}</label><SnmpPollFields v-if="form.responder" :poll="form.poll" responder/></template>
      <p class="form-note">{{t('Zuerst Gerät mit Trap-Zugangsdaten und Abfrageziel speichern. Danach die gespeicherte Senderidentität prüfen, ausdrücklich in den Entwurf übernehmen und mit erneut eingegebenen Trap-Zugangsdaten speichern. Die Prüfung allein erteilt keine Freigabe.')}}</p>
      <button ref="probeButton" type="button" class="refresh sender-probe-action" :disabled="busy || !enrollmentMatches(form,entry)" @click="run('snmp_trap_probe')">{{probing?t('Senderidentität wird geprüft …'):t('Gespeicherte Senderidentität prüfen')}}</button>
      <div v-if="identity" class="notice" role="status"><strong>{{t('Senderidentität authentifiziert · Freigabe ausstehend')}}</strong><p>{{t('Geprüftes Ziel:')}} {{identity.target}} · {{t('Engine-ID:')}} <code>{{identity.engine_id}}</code> · {{t('Boots-Zähler:')}} {{identity.engine_boots}}</p><button type="button" class="refresh" @click="approveEngine(form,identity,entry)">{{t('Geprüfte Engine-ID in Entwurf übernehmen')}}</button><p>{{t('Die Übernahme ersetzt die bisherige Senderfreigabe im Entwurf. Die Änderung wird erst mit Speichern wirksam.')}}</p></div>
      </template>
      </template>
      <div class="form-columns"><label>{{t("Pause zwischen Abfragen (Sekunden)")}}<input v-model="form.interval_seconds" type="number" min="30" max="86400" step="1" required></label><label v-if="form.repeat">{{t("Alarmwiederholung (Minuten)")}}<input v-model="form.repeat_minutes" type="number" min="5" step="1" required></label></div>
      <template v-if="form.primary_protocol==='redfish'">
      <div class="form-columns"><label>{{t("Hardwarelog lesen")}}<select v-model="form.hardware_log_mode"><option value="disabled">{{t("Deaktiviert")}}</option><option value="all">{{t("Alle verfügbaren Einträge")}}</option><option value="latest">{{t("Die neuesten N Einträge")}}</option></select></label><label v-if="form.hardware_log_mode==='latest'">{{t("Anzahl Hardwarelog-Einträge")}}<input v-model="form.hardware_log_limit" type="number" min="1" max="4096" step="1" required></label></div>
      <p class="form-note">{{t("Die Aufbewahrungsfrist gilt unabhängig von der Abfragemenge. Bereits gespeicherte junge Einträge bleiben erhalten. Die begrenzte Abfrage benötigt Unterstützung für eine chronologische Auswahl durch den Controller; fehlende Unterstützung wird als Abfrageproblem angezeigt.")}}</p>
      </template>
      <label class="check"><input v-model="form.enabled" type="checkbox">{{t("Überwachung aktiv")}}</label>
      <label class="check"><input v-model="form.repeat" type="checkbox">{{t("Anhaltende Alarme regelmäßig erneut erfassen")}}</label>
      <label class="check"><input v-model="form.alerts_enabled" type="checkbox">{{t("Benachrichtigungen für dieses Gerät aktivieren")}}</label>
      <p class="form-note">{{t("Alarmzustände und Ereignisse werden lokal gespeichert. Diese Geräteoption erlaubt den Versand über die aktivierten Kanäle (E-Mail und/oder DSM-Desktop). Kanäle und Ereignisauswahl werden unter Benachrichtigungen eingestellt.")}}</p>
    </fieldset>
    <div v-if="error" class="error" role="alert">{{t(error)}}</div>
    <div v-if="result?.protocol==='snmp'" class="notice" role="status"><strong>{{t('SNMP-Datenzugriff bestätigt')}}</strong><p>{{result.version}} · {{securityLabel(result.version)}} · {{profileLabel(result.profile)}} · {{result.elapsed_ms}} ms</p><p>{{result.target}} · {{result.sys_object_id}}</p><p v-if="result.engine_id">{{t('Engine-ID:')}} <code>{{result.engine_id}}</code> · {{t('Boots-Zähler:')}} {{result.engine_boots}}</p><p>{{result.complete?t('Angeforderte Datenbereiche vollständig abgefragt.'):t('Hardwareabdeckung unvollständig. Systemidentität allein genügt nicht.')}}</p><ul><li v-for="c in result.capabilities" :key="c.uri">{{c.uri}} · {{capabilityText(c)}}</li></ul></div>
    <div v-else-if="result" class="notice" role="status"><strong>{{t("Redfish-Verbindung bestätigt")}}</strong><p v-if="result.redfish_version">Redfish {{result.redfish_version}}</p><p v-if="result.certificate_fingerprint">{{t("Zertifikat SHA-256:")}} <code>{{result.certificate_fingerprint}}</code></p><p>{{result.checked_collections?t("HTTPS und Zugriff auf {0} Datenbereiche bestätigt. Hardwarezustände werden nach dem Speichern regelmäßig abgefragt.",result.checked_collections):t("Nur die Redfish-Startseite wurde erreicht. Anmeldung und Zugriff auf Hardwaredaten sind noch nicht bestätigt.")}}</p></div>
    <div v-if="confirmDelete" class="error"><p>{{t("Das Gerät und seine Zugangsdaten entfernen? Bisherige Ereignisse und das Änderungsprotokoll bleiben erhalten.")}}</p><button type="button" class="danger" :disabled="busy" @click="run('delete')">{{t("Endgültig entfernen")}}</button><button type="button" class="refresh" :disabled="busy" @click="confirmDelete=false">{{t("Behalten")}}</button></div>
    <footer><button v-if="old && !confirmDelete" type="button" class="danger-outline" :disabled="busy" @click="confirmDelete=true">{{t("Gerät entfernen")}}</button><span class="spacer"></span><button type="button" class="refresh" :disabled="busy" @click="close">{{t("Abbrechen")}}</button><button type="button" class="refresh" :disabled="busy" @click="run('test')">{{t("Verbindung prüfen")}}</button><button type="submit" class="primary" :disabled="busy">{{busy?t("Wird ausgeführt …"):t("Speichern")}}</button></footer>
  </form>
</section></div>
</template>
