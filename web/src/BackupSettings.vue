<script setup>
import {t} from './i18n.js';
import {computed,ref,onMounted,onUnmounted} from 'vue';
import {administer} from './device-api.js';
import {waitJob,uploadFile} from './maintenance.js';
import {downloadBackup} from './backup-download.js';
import {timestamp} from './health.js';
const props=defineProps({dashboard:Object});const emit=defineEmits(['changed']);
const password=ref(''),repeat=ref(''),file=ref(null),summary=ref(null),confirmation=ref('');
const busy=ref(false),error=ref(''),message=ref(''),job=ref(''),download=ref(''),progress=ref(null);
const downloading=ref(false);
let controller,downloadController;
const validPassword=computed(()=>[...password.value].length>=12&&new TextEncoder().encode(password.value).length<=1024);
function invalidate(){summary.value=null;confirmation.value='';}
function selected(event){invalidate();file.value=event.target.files?.[0]??null;error.value='';}
onUnmounted(()=>{controller?.abort();downloadController?.abort();password.value='';repeat.value='';});
async function wait(id){return waitJob(()=>props.dashboard,id,{signal:controller.signal,onProgress:value=>progress.value=value});}
function begin(){controller=new AbortController();busy.value=true;error.value='';message.value='';progress.value=null;}
async function cancel(){try{if(job.value)await administer(props.dashboard,{action:'job_cancel',id:job.value});controller?.abort();}catch(e){error.value=e.message;}}
async function discard(){
 busy.value=true;error.value='';
 try{
  const ids=new Set([job.value,...(props.dashboard.jobs??[]).filter(j=>['export','upload'].includes(j.kind)).map(j=>j.id)].filter(Boolean));
  let failure;for(const id of ids){try{await administer(props.dashboard,{action:'job_cancel',id});}catch(e){failure=e;}}
  job.value='';download.value='';invalidate();emit('changed');if(failure)error.value=failure.message;
 }catch(e){error.value=e.message;}finally{busy.value=false;}
}
async function downloadNow(){
 if(downloading.value||busy.value)return;
 downloading.value=true;error.value='';downloadController=new AbortController();
 const timeout=setTimeout(()=>downloadController.abort(),25000);
 try{await downloadBackup(download.value,{signal:downloadController.signal});}
 catch(e){error.value=e.name==='AbortError'?t("Zeitüberschreitung beim Download. Bitte erneut versuchen."):e.message;}
 finally{clearTimeout(timeout);downloading.value=false;}
}
async function perform(action){
 begin();
 if(action!=='restore')invalidate();
 try{
  if(action==='export'){
   const result=await administer(props.dashboard,{action:'backup_export_start',password:password.value},fetch,controller.signal);
   job.value=result.job;await wait(job.value);download.value=job.value;
   message.value=t("Verschlüsselte Sicherung zum Download bereitgestellt. Bewahre das Passwort getrennt davon auf.");
   password.value='';repeat.value='';emit('changed');
  }else if(action==='inspect'){
   const result=await administer(props.dashboard,{action:'backup_upload_start'},fetch,controller.signal);job.value=result.job;
   await uploadFile(()=>props.dashboard,job.value,file.value,{signal:controller.signal,onProgress:bytes=>progress.value={phase:'upload',bytes}});
   await administer(props.dashboard,{action:'backup_inspect_start',id:job.value,bytes:file.value.size,password:password.value},fetch,controller.signal);
   summary.value=await wait(job.value);password.value='';repeat.value='';
  }else{
   await administer(props.dashboard,{action:'backup_restore_start',id:job.value,expected_audit:summary.value.expected_audit,confirm:true},fetch,controller.signal);
   await wait(job.value);message.value=t("Wiederherstellung abgeschlossen. Überwachung und automatische Benachrichtigungen sind pausiert.");
   invalidate();file.value=null;emit('changed');
  }
 }catch(e){error.value=e.name==='AbortError'?t("Der Auftrag wurde abgebrochen."):e.message;}
 finally{busy.value=false;}
}
onMounted(async()=>{
 const existing=[...(props.dashboard?.jobs??[])].filter(j=>['export','upload'].includes(j.kind)&&['running','ready'].includes(j.status.state)).sort((a,b)=>b.created-a.created);
 const running=existing.find(j=>j.status.state==='running');
 const inspected=existing.find(j=>j.kind==='upload'&&j.status.state==='ready'&&j.status.result?.expected_audit!=null);
 const exported=existing.find(j=>j.kind==='export'&&j.status.state==='ready');
 if(exported)download.value=exported.id;
 if(inspected){job.value=inspected.id;summary.value=inspected.status.result;}
 if(running){invalidate();begin();job.value=running.id;try{const result=await wait(job.value);if(running.kind==='export')download.value=job.value;else if(result.restored)message.value=t("Wiederherstellung abgeschlossen. Überwachung und automatische Benachrichtigungen sind pausiert.");else summary.value=result;}catch(e){error.value=e.message;}finally{busy.value=false;}}
});
</script>
<template><section class="panel device-editor backup-settings">
 <header><h2>{{t("Sicherung & Wiederherstellung")}}</h2><p class="form-note">{{t("Vollständige, komprimierte und verschlüsselte Sicherungen. Grosse Dateien werden im Hintergrund stückweise verarbeitet.")}}</p></header>
 <fieldset :disabled="busy||downloading">
  <label>{{t("Sicherungspasswort")}}<input v-model="password" type="password" autocomplete="new-password" maxlength="1024" @input="invalidate"><small>{{t("Mindestens 12 Zeichen (UTF-8). Das Passwort wird nicht gespeichert und lässt sich nicht zurücksetzen.")}}</small></label>
  <div class="form-columns"><div><h3>{{t("Neue Sicherung")}}</h3><label>{{t("Passwort wiederholen")}}<input v-model="repeat" type="password" autocomplete="new-password" maxlength="1024"></label>
   <button class="primary" :disabled="!validPassword||password!==repeat" @click="perform('export')">{{t("Verschlüsselte Sicherung erstellen")}}</button>
   <p class="form-note">{{t("Enthält Geräte, Zugangsdaten, Zertifikate, Einstellungen, Alarmzustände und gespeicherte Historie. Der lokale Hauptschlüssel wird nicht exportiert.")}}</p>
   <button v-if="download" type="button" class="refresh" :disabled="downloading" @click="downloadNow">{{downloading?t("Download wird geprüft …"):t("Fertige Sicherung herunterladen")}}</button>
  </div><div><h3>{{t("Bestehende Sicherung")}}</h3>
   <label>{{t("Sicherungsdatei")}}<input type="file" accept=".hmbackup" @change="selected"></label><p v-if="file">{{file.name}}</p>
   <button class="refresh" :disabled="!validPassword||!file" @click="perform('inspect')">{{t("Datei und Passwort prüfen")}}</button>
   <div v-if="summary" class="maintenance-confirm"><strong>{{t("Dateiformat und Passwort geprüft")}}</strong>
    <p>Version {{summary.version}} · {{timestamp(summary.created)}}<br>{{summary.devices}} {{t("Geräte ·")}} {{summary.alarms}} {{t("gespeicherte Zustände ·")}} {{summary.events}} {{t("Ereignisse")}}</p>
    <p>{{t("Ersetzt den aktuellen Gerätebestand, Einstellungen, Alarmzustände und Ereignisse. Das bestehende Änderungsprotokoll bleibt erhalten und wird ergänzt. Ausstehende Sendungen der Sicherung werden storniert. Alle wiederhergestellten Geräte und automatischen Benachrichtigungen bleiben pausiert; prüfe sie anschließend und aktiviere sie einzeln. Sichere zuvor bei Bedarf den aktuellen Stand.")}}</p>
    <label>{{t("Zur Bestätigung WIEDERHERSTELLEN eingeben")}}<input v-model="confirmation" autocomplete="off"></label>
    <button class="danger" :disabled="confirmation!==t('WIEDERHERSTELLEN')" @click="perform('restore')">{{t("Datenbestand ersetzen und wiederherstellen")}}</button>
   </div>
  </div></div>
 </fieldset>
 <p v-if="busy" role="status">{{t("Auftrag wird verarbeitet …")}} <span v-if="progress">{{progress.rows??0}} {{t("Datensätze")}} · {{((progress.bytes??0)/1048576).toFixed(1)}} MiB</span></p>
 <button v-if="busy" class="refresh" @click="cancel">{{t("Abbrechen")}}</button>
 <p v-if="message" role="status">{{message}}</p><p v-if="error" class="error" role="alert">{{error}}</p>
 <button v-if="job||download||(dashboard.jobs??[]).some(j=>['export','upload'].includes(j.kind))" class="refresh" :disabled="busy||downloading" @click="discard">{{t("Temporäre Sicherungsaufträge verwerfen")}}</button>
 <p class="form-note">{{t("Fertige Aufträge sind eine Stunde verfügbar und an deine Sitzung gebunden. Für temporäre Dateien ist freier Platz auf dem NAS erforderlich. Bestehende Sicherungsdateien bleiben lesbar.")}}</p>
</section></template>
