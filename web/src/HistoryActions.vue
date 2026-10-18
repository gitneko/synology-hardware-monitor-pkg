<script setup>
import {t} from './i18n.js';
import {ref} from 'vue';
import {administer} from './device-api.js';
import {downloadFile,downloadName} from './download.js';
const props=defineProps({dashboard:Object,filter:Object});const emit=defineEmits(['changed']);
const busy=ref(false),error=ref(''),message=ref(''),confirm=ref(false);
async function perform(action){
  busy.value=true;error.value='';message.value='';
  try {
    const data=await administer(props.dashboard,action==='events_export'?{action,filter:{...props.filter}}:{action,confirm:true});
    if(action==='events_export'){downloadFile(data.file,downloadName('csv'),'text/csv;charset=utf-8');message.value=t("{0} Ereignisse exportiert.",data.count);}
    else{message.value=t("{0} Ereignisse gelöscht. Aktive Alarmzustände bleiben erhalten.",data.count);confirm.value=false;}
    emit('changed');
  }catch(e){error.value=e.message;}finally{busy.value=false;}
}
</script>
<template><div class="history-actions"><div class="action-row"><button class="refresh" :disabled="busy" @click="perform('events_export')">{{t("CSV exportieren")}}</button><button class="danger-outline" :disabled="busy" @click="confirm=true">{{t("Ereignislog leeren …")}}</button></div><p class="form-note">{{t("CSV: alle gespeicherten Ereignisse passend zur aktuellen Auswahl, einschließlich einzelner Sammelmeldungen. Die Anzeige oben ist auf die letzten 100 Ereignisse begrenzt.")}}</p><p v-if="message" role="status">{{message}}</p><p v-if="error" class="error" role="alert">{{error}}</p><div v-if="confirm" class="maintenance-confirm" role="group" :aria-label="t(&quot;Ereignislog leeren bestätigen&quot;)"><strong>{{t("Gesamtes Ereignislog leeren?")}}</strong><p>{{t("Alle Ereignisse aller Geräte und deren ausstehende E-Mail- und Desktopsendungen werden gelöscht, unabhängig von der aktuellen Auswahl. Aktive Alarmzustände, die Hardwarelog-Duplikaterkennung und das Änderungsprotokoll bleiben erhalten. Die Aktion wird im Änderungsprotokoll festgehalten. Die nächste Alarmwiederholung folgt frühestens nach dem eingestellten Wiederholungsintervall.")}}</p><button class="danger" :disabled="busy" @click="perform('events_clear')">{{busy?t("Wird geleert …"):t("Gesamtes Ereignislog jetzt leeren")}}</button> <button class="refresh" :disabled="busy" @click="confirm=false">{{t("Abbrechen")}}</button></div></div></template>
