<script setup>
import {t} from './i18n.js';
import {ref,reactive,watch,onMounted,onUnmounted} from 'vue';
import {administer} from './device-api.js';
const props=defineProps({entry:Object,dashboard:Object});
const emit=defineEmits(['close','saved']);
const old=props.entry?.device;
const form=reactive({name:old?.name??'',endpoint:old?.endpoint??'https://',username:old?.username??'',password:'',interval_seconds:old?.interval_seconds??60,repeat:old?.repeat_seconds!=null,repeat_minutes:(old?.repeat_seconds??300)/60,alerts_enabled:old?.alerts_enabled??false,enabled:old?.enabled??true,tls_profile:old?.tls_profile??'standard',trust_mode:old?.custom_trust?'keep':'system',certificate_pem:''});
const busy=ref(false),error=ref(''),result=ref(null),confirmDelete=ref(false),nameField=ref(null);
watch(()=>form.tls_profile,()=>{form.trust_mode=form.tls_profile==='idrac7'?'pinned':'system';form.certificate_pem='';});
watch(form,()=>{result.value=null;error.value='';confirmDelete.value=false;});
let controller;
const previousFocus=document.activeElement;
onMounted(()=>nameField.value?.focus());
onUnmounted(()=>{controller?.abort();form.password='';previousFocus?.focus();});
function close(){if(!busy.value){form.password='';emit('close');}}
function input(){return {id:old?.id??null,revision:props.entry?.revision??null,name:form.name,endpoint:form.endpoint.trim(),username:form.username,password:form.password||null,interval_seconds:Number(form.interval_seconds),repeat_seconds:form.repeat?Number(form.repeat_minutes)*60:null,alerts_enabled:form.alerts_enabled,enabled:form.enabled,tls_profile:form.tls_profile,trust_mode:form.trust_mode,certificate_pem:['custom','pinned'].includes(form.trust_mode)?form.certificate_pem:null};}
async function run(action){
  if(busy.value)return;
  busy.value=true;error.value='';result.value=null;controller=new AbortController();
  const timeout=setTimeout(()=>controller.abort(),25000);
  try{
    const operation=action==='delete'?{action,id:old.id,revision:props.entry.revision}:{action,device:input()};
    const body=await administer(props.dashboard,operation,fetch,controller.signal);
    if(action==='test')result.value=body.connection;
    else{form.password='';emit('saved',body.id??null);}
  }catch(e){error.value=e.name==='AbortError'?t("Zeitüberschreitung. Bitte aktualisieren und das Ergebnis prüfen."):e.message;}
  finally{clearTimeout(timeout);busy.value=false;}
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
  <form @submit.prevent="run('save')">
    <fieldset :disabled="busy"><legend class="sr-only">{{t("Geräteangaben")}}</legend>
      <label>Name<input ref="nameField" v-model="form.name" required maxlength="160" :placeholder="t(&quot;Zum Beispiel: Dell R340&quot;)" autocomplete="off"></label>
      <label>{{t("HTTPS-Adresse")}}<input v-model="form.endpoint" type="url" required placeholder="https://idrac.example.local/" autocomplete="off"><small>{{t("Die Management-Adresse ohne Redfish-Pfad. HTTPS-Zertifikate werden immer geprüft.")}}</small></label>
      <div class="form-columns"><label>{{t("Gerätebenutzer")}}<input v-model="form.username" required maxlength="128" autocomplete="off"></label><label>{{old?t("Passwort ersetzen (optional)"):t("Gerätepasswort")}}<input v-model="form.password" type="password" :required="!old" maxlength="4096" autocomplete="new-password"><small v-if="old">{{t("Leer lassen, um es zu behalten. Bei neuer Adresse oder neuem Benutzer ist ein Passwort erforderlich.")}}</small></label></div>
      <label>{{t("Verbindungsmodus")}}<select v-model="form.tls_profile"><option value="standard">{{t("Standard")}}</option><option value="idrac7">{{t("iDRAC7/8-Kompatibilität")}}</option></select></label>
      <label>{{t("Zertifikatsvertrauen")}}<select v-model="form.trust_mode"><option v-if="old?.custom_trust && form.tls_profile===(old?.tls_profile??'standard')" value="keep">{{t("Gespeichertes Zertifikat beibehalten")}}</option><template v-if="form.tls_profile==='standard'"><option value="system">{{t("Öffentlich vertrauenswürdiges Zertifikat")}}</option><option value="custom">{{t("Eigene CA oder Serverzertifikat importieren")}}</option></template><option v-else value="pinned">{{t("Genau diesem Serverzertifikat vertrauen")}}</option></select></label>
      <p v-if="form.tls_profile==='idrac7'" class="form-note">{{t("Importiere das Serverzertifikat des Controllers aus einer vertrauenswürdigen Quelle. Nur dieses Zertifikat wird akzeptiert; Name und CA-Kennzeichnung werden durch den exakten Zertifikatsvergleich ersetzt. Die zeitliche Gültigkeit wird weiterhin geprüft. Bei Zertifikatswechsel erneut importieren.")}}</p>
      <p v-if="form.tls_profile==='idrac7'" class="form-note">{{t("Bei älteren iDRAC-Controllern darf eine vollständige Abfrage bis zu fünf Minuten dauern. Die eingestellte Pause beginnt nach Abschluss der vorherigen Abfrage.")}}</p>
      <p v-if="form.trust_mode==='keep' && old?.certificate_fingerprint" class="form-note">{{t("Zertifikat SHA-256:")}} <code>{{old.certificate_fingerprint}}</code></p>
      <div v-if="['custom','pinned'].includes(form.trust_mode)" class="certificate-input"><label>{{t("Zertifikatsdatei (PEM)")}}<input type="file" accept=".pem,.crt,.cer" @change="importCertificate"></label><label>{{t("PEM-Zertifikat")}}<textarea v-model="form.certificate_pem" rows="4" required spellcheck="false" placeholder="-----BEGIN CERTIFICATE-----"></textarea></label><small>{{form.tls_profile==='idrac7'?t("Ein einzelnes Serverzertifikat, kein privater Schlüssel."):t("Nur Zertifikate, keine privaten Schlüssel. Der Hostname muss weiterhin zum Zertifikat passen.")}}</small></div>
      <div class="form-columns"><label>{{t("Pause zwischen Abfragen (Sekunden)")}}<input v-model="form.interval_seconds" type="number" min="30" max="86400" step="1" required></label><label v-if="form.repeat">{{t("Alarmwiederholung (Minuten)")}}<input v-model="form.repeat_minutes" type="number" min="5" step="1" required></label></div>
      <label class="check"><input v-model="form.enabled" type="checkbox">{{t("Überwachung aktiv")}}</label>
      <label class="check"><input v-model="form.repeat" type="checkbox">{{t("Anhaltende Alarme regelmäßig erneut erfassen")}}</label>
      <label class="check"><input v-model="form.alerts_enabled" type="checkbox">{{t("Benachrichtigungen für dieses Gerät aktivieren")}}</label>
      <p class="form-note">{{t("Alarmzustände und Ereignisse werden lokal gespeichert. Diese Geräteoption erlaubt den Versand über die aktivierten Kanäle (E-Mail und/oder DSM-Desktop). Kanäle und Ereignisauswahl werden unter Benachrichtigungen eingestellt.")}}</p>
    </fieldset>
    <div v-if="error" class="error" role="alert">{{error}}</div>
    <div v-if="result" class="notice" role="status"><strong>{{t("Redfish-Verbindung bestätigt")}}</strong><p v-if="result.redfish_version">Redfish {{result.redfish_version}}</p><p v-if="result.certificate_fingerprint">{{t("Zertifikat SHA-256:")}} <code>{{result.certificate_fingerprint}}</code></p><p>{{result.checked_collections?t("HTTPS und Zugriff auf {0} Datenbereiche bestätigt. Hardwarezustände werden nach dem Speichern regelmäßig abgefragt.",result.checked_collections):t("Nur die Redfish-Startseite wurde erreicht. Anmeldung und Zugriff auf Hardwaredaten sind noch nicht bestätigt.")}}</p></div>
    <div v-if="confirmDelete" class="error"><p>{{t("Das Gerät und seine Zugangsdaten entfernen? Bisherige Ereignisse und das Änderungsprotokoll bleiben erhalten.")}}</p><button type="button" class="danger" :disabled="busy" @click="run('delete')">{{t("Endgültig entfernen")}}</button><button type="button" class="refresh" :disabled="busy" @click="confirmDelete=false">{{t("Behalten")}}</button></div>
    <footer><button v-if="old && !confirmDelete" type="button" class="danger-outline" :disabled="busy" @click="confirmDelete=true">{{t("Gerät entfernen")}}</button><span class="spacer"></span><button type="button" class="refresh" :disabled="busy" @click="close">{{t("Abbrechen")}}</button><button type="button" class="refresh" :disabled="busy" @click="run('test')">{{t("Verbindung prüfen")}}</button><button type="submit" class="primary" :disabled="busy">{{busy?t("Wird ausgeführt …"):t("Speichern")}}</button></footer>
  </form>
</section></div>
</template>
