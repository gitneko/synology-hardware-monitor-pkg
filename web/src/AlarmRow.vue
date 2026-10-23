<script setup>
import {computed,ref} from 'vue';
import {t} from './i18n.js';
import {labels,timestamp,alarmConfirmation,coveredLabels} from './health.js';
import {administer} from './device-api.js';
import {acknowledgementOperation,resetAlarmOperation} from './alarm-actions.js';
const props=defineProps({alarm:Object,device:Object,dashboard:Object});
const emit=defineEmits(['changed']);
const target=ref(null);
const dialog=ref(null),reason=ref(''),error=ref(''),busy=ref(false);
const status=computed(()=>props.alarm.assessment?.status??props.alarm.health);
const ownAcknowledged=computed(()=>props.alarm.assessment?.acknowledged??(status.value==='acknowledged'));
const acknowledgement=computed(()=>props.alarm.assessment?.acknowledgement);
const editable=computed(()=>props.dashboard?.user?.role==='administrator' && props.alarm.assessment?.token && !props.alarm.assessment.derived && props.alarm.key!=='collector' && !props.alarm.key.startsWith('coverage:') && !props.alarm.key.startsWith('log:'));
const resetting=computed(()=>target.value?.mode==='reset');
const dialogTitle=computed(()=>resetting.value?t('Gespeicherten Alarm zurücksetzen'):target.value?.acknowledged===false?t('Bestätigung aufheben'):t('Hardwarealarm bestätigen'));
function open(mode='acknowledge'){
  target.value={mode,device:{device:{id:props.device.device.id},revision:props.device.revision},alarm:{...props.alarm,assessment:{...props.alarm.assessment}},acknowledged:!ownAcknowledged.value};
  reason.value=acknowledgement.value?.needs_review?acknowledgement.value.reason:'';error.value='';dialog.value.showModal();
}
async function save(){
  busy.value=true;error.value='';
  try{
    await administer(props.dashboard,resetting.value?resetAlarmOperation(target.value.device,target.value.alarm,true):acknowledgementOperation(target.value.device,target.value.alarm,target.value.acknowledged,reason.value));
    dialog.value?.close();emit('changed');
  }catch(e){error.value=e.message;}finally{busy.value=false;}
}
</script>
<template>
<div class="alarm">
  <span :class="['badge',status]">{{labels[status]}}</span> {{alarm.label}}
  <small v-if="status!==alarm.health">{{t('Hardwarezustand:')}} {{labels[alarm.health]}}</small>
  <small>{{alarmConfirmation(alarm)}} {{t('· Zuletzt gemessen:')}} {{timestamp(alarm.observed)}}</small>
  <small v-if="alarm.covered_by?.length">{{t('Benachrichtigung gebündelt mit:')}} {{coveredLabels(alarm,device)}}</small>
  <small v-if="alarm.assessment?.derived && status==='acknowledged'">{{t('Durch bestätigte Komponentenfehler abgedeckt.')}}</small>
  <small v-if="acknowledgement"><strong v-if="acknowledgement.needs_review">{{t('Importierte Bestätigung prüfen:')}}</strong> {{t('Bestätigt von {0} am {1}',acknowledgement.actor,timestamp(acknowledgement.created))}}<br>{{acknowledgement.reason}}</small>
  <button v-if="editable" class="refresh alarm-action" @click="open('acknowledge')">{{ownAcknowledged?t('Bestätigung aufheben …'):t('Bestätigen …')}}</button>
  <button v-if="editable" class="refresh alarm-action" @click="open('reset')">{{t('Gespeicherten Alarm zurücksetzen …')}}</button>
  <dialog ref="dialog" class="device-editor alarm-dialog" :aria-label="dialogTitle" @cancel="busy && $event.preventDefault()">
    <form @submit.prevent="save">
      <h2>{{dialogTitle}}</h2>
      <p>{{target?.alarm.label??alarm.label}} · {{labels[target?.alarm.health??alarm.health]}}</p>
      <p v-if="resetting" class="form-note">{{t('Der gespeicherte Alarm und seine Bestätigung werden entfernt. Die Ereignishistorie und die aktuellen Messwerte bleiben erhalten. Noch ausstehende automatische Meldungen dazu werden storniert. Ein weiterhin gemeldeter Fehler wird bei der nächsten Abfrage erneut als neuer Alarm angelegt.')}}</p>
      <p v-else class="form-note">{{target?.acknowledged===false?t('Ein weiterhin anstehender Fehler wird bei aktuellen Messdaten einmal neu gemeldet. Andernfalls wartet die Meldung auf eine gültige Abfrage.'):t('E-Mail und DSM-Desktopmeldungen für diesen Fehlerfall werden unterdrückt. OK, eine Verschlechterung oder neue erkennbare Fehlermerkmale beenden die Bestätigung. Neue Hardwarelog-Einträge bleiben separat aktiv.')}}</p>
      <label v-if="!resetting && target?.acknowledged!==false">{{t('Begründung')}}<textarea v-model="reason" required maxlength="1000" rows="3" :disabled="busy"/></label>
      <p v-if="error" class="error" role="alert">{{error}}</p>
      <footer><button type="button" class="refresh" :disabled="busy" @click="dialog.close()">{{t('Abbrechen')}}</button><button type="submit" class="primary" :disabled="busy">{{busy?t('Wird gespeichert …'):resetting?t('Alarm jetzt zurücksetzen'):target?.acknowledged===false?t('Bestätigung jetzt aufheben'):t('Bestätigen und Meldungen unterdrücken')}}</button></footer>
    </form>
  </dialog>
</div>
</template>
