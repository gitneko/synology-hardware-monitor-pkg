<script setup>
import {t} from './i18n.js';
import {ref,reactive,computed,watch,onUnmounted} from 'vue';
import {administer} from './device-api.js';
import {waitJob} from './maintenance.js';
const props=defineProps({dashboard:Object});const emit=defineEmits(['changed']);
const saved=ref({...props.dashboard.history.settings});
const form=reactive({...saved.value});const revision=ref(props.dashboard.history.revision);
const busy=ref(false),error=ref(''),message=ref(''),job=ref(''),preview=ref(null),processed=ref(0);
const valid=computed(()=>[form.events_days,form.hardware_logs_days].every(v=>Number.isInteger(v)&&v>=0&&v<=36500));
const dirty=computed(()=>form.events_days!==saved.value.events_days||form.hardware_logs_days!==saved.value.hardware_logs_days);
let controller;
watch(()=>props.dashboard.history.revision,()=>{if(!dirty.value){saved.value={...props.dashboard.history.settings};Object.assign(form,saved.value);revision.value=props.dashboard.history.revision;preview.value=null;}});
watch(form,()=>preview.value=null);
onUnmounted(()=>controller?.abort());
async function cancel(){try{if(job.value)await administer(props.dashboard,{action:'job_cancel',id:job.value});controller?.abort();}catch(e){error.value=e.message;}}
function reload(){saved.value={...props.dashboard.history.settings};Object.assign(form,saved.value);revision.value=props.dashboard.history.revision;preview.value=null;error.value='';}
async function perform(action){
 busy.value=true;error.value='';message.value='';controller=new AbortController();
 try{
  if(action==='save'){
   const result=await administer(props.dashboard,{action:'retention_save',settings:{events_days:Number(form.events_days),hardware_logs_days:Number(form.hardware_logs_days)},revision:revision.value},fetch,controller.signal);
   revision.value=result.revision;saved.value={...form};preview.value=null;message.value=t("Aufbewahrungsregeln gespeichert.");emit('changed');
  }else{
   if(action==='run'&&!window.confirm(t("Jetzt {0} Ereignisse und {1} Hardwarelogs nach den gespeicherten Regeln löschen?",preview.value.counts.events,preview.value.counts.hardware_logs)))return;
   const result=await administer(props.dashboard,action==='preview'?{action:'cleanup_preview'}:{action:'cleanup_run',id:job.value,confirm:true},fetch,controller.signal);
   job.value=result.job;
   const finished=await waitJob(()=>props.dashboard,job.value,{signal:controller.signal,onProgress:status=>processed.value=status.rows});
   if(action==='preview')preview.value=finished;
   else{message.value=t("Bereinigung abgeschlossen: {0} Ereignisse und {1} Hardwarelogs entfernt.",finished.counts.events,finished.counts.hardware_logs);preview.value=null;emit('changed');}
  }
 }catch(e){error.value=e.name==='AbortError'?t("Der Auftrag wurde abgebrochen."):e.message;}
 finally{busy.value=false;}
}
</script>
<template><section class="panel device-editor history-settings">
 <h2>{{t("Aufbewahrung & Bereinigung")}}</h2>
 <p class="form-note">{{t("Ereignisse und Hardwarelogs haben getrennte Aufbewahrungsfristen. Standard sind jeweils 90 Tage; 0 bedeutet unbegrenzt. Die automatische Bereinigung läuft täglich im Dienst, auch bei deaktivierter Geräteabfrage.")}}</p>
 <fieldset :disabled="busy"><div class="form-columns">
  <label>{{t("Ereignishistorie aufbewahren (Tage)")}}<input v-model.number="form.events_days" type="number" min="0" max="36500" step="1" required></label>
  <label>{{t("Hardwarelogs aufbewahren (Tage)")}}<input v-model.number="form.hardware_logs_days" type="number" min="0" max="36500" step="1" required></label>
 </div>
 <button class="primary" :disabled="!dirty||!valid" @click="perform('save')">{{t("Aufbewahrungsregeln speichern")}}</button>
 <button v-if="dirty||revision!==dashboard.history.revision" class="refresh" @click="reload">{{t("Gespeicherte Regeln neu laden")}}</button>
 <button class="refresh" :disabled="dirty" @click="perform('preview')">{{t("Bereinigung prüfen")}}</button>
 <div v-if="preview" class="maintenance-confirm">
  <p>{{t("Zur Bereinigung vorgesehen: {0} Ereignisse und {1} Hardwarelogs.",preview.counts.events,preview.counts.hardware_logs)}}</p>
  <p>{{t("{0} Hardwarelogs ohne verlässlichen Zeitstempel bleiben erhalten.",preview.counts.undated_hardware_logs)}}</p>
  <button class="danger" :disabled="dirty" @click="perform('run')">{{t("Jetzt bereinigen")}}</button>
 </div></fieldset>
 <p class="form-note">{{t("Aktive Alarmzustände und ausstehende Sendungen bleiben erhalten. Bereits zu alte Hardwarelogs werden nicht erneut importiert. Fehlende, ungültige und zukünftige Controllerzeitstempel werden vorsichtshalber nicht automatisch bereinigt.")}}</p>
 <p class="form-note">{{t("Ein Abbruch stoppt die weitere Bereinigung. Bereits entfernte Datensätze bleiben gelöscht.")}}</p>
 <p class="form-note">{{t("Das Änderungsprotokoll speichert die neuesten 10'000 Einträge. Diese Grenze ist unabhängig von den beiden Aufbewahrungsfristen.")}}</p>
 <p v-if="busy" role="status">{{t("Auftrag wird verarbeitet …")}} {{processed}} {{t("Datensätze")}} <button class="refresh" @click="cancel">{{t("Abbrechen")}}</button></p>
 <p v-if="message" role="status">{{message}}</p><p v-if="error" class="error" role="alert">{{error}}</p>
</section></template>
