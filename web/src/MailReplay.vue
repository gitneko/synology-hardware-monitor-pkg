<script setup>
import {computed,onMounted,onUnmounted,ref,watch} from 'vue';
import {t} from './i18n.js';
import {timestamp} from './health.js';
import {administer} from './device-api.js';
import {replayPreviewOperation,replaySendOperation,replayStatus,replayError} from './mail-replay.js';
const props=defineProps({event:Object,dashboard:Object});
const emit=defineEmits(['close','changed']);
const recipients=computed(()=>props.dashboard?.mail?.settings?.recipients??[]);
const recipient=ref(recipients.value[0]??''),preview=ref(null),history=ref([]),busy=ref(false),error=ref(''),message=ref(''),sent=ref(false),closeButton=ref(null);
const allowed=computed(()=>props.dashboard?.user?.role==='administrator');
watch(recipient,()=>{preview.value=null;sent.value=false;message.value='';});
watch(()=>props.dashboard?.mail?.revision,()=>{preview.value=null;sent.value=false;});
let controller,timer;
const previousFocus=typeof document==='undefined'?null:document.activeElement;
async function request(operation){
  controller=new AbortController();const timeout=setTimeout(()=>controller.abort(),15000);
  try{return await administer(props.dashboard,operation,fetch,controller.signal);}
  finally{clearTimeout(timeout);}
}
async function loadHistory(){
  if(busy.value||!allowed.value)return;
  busy.value=true;
  try{history.value=(await request({action:'mail_replay_history',event_id:props.event.id})).history;}
  catch(e){error.value=e.message;}
  finally{busy.value=false;}
}
async function perform(send){
  if(busy.value||!allowed.value)return;
  busy.value=true;error.value='';message.value='';
  try{
    if(send){
      const result=await request(replaySendOperation(preview.value,props.event,recipient.value));
      sent.value=true;message.value=replayStatus(result.job);
      history.value=(await request({action:'mail_replay_history',event_id:props.event.id})).history;
      emit('changed');
    }else{
      preview.value=null;sent.value=false;
      preview.value=(await request(replayPreviewOperation(props.event,recipient.value,recipients.value))).preview;
    }
  }catch(e){
    // Keep the same preview after a lost submission response: retrying its ID
    // only looks up the same durable job, never creates another email.
    error.value=e.name==='AbortError'?t('Keine rechtzeitige Bestätigung. Versandverlauf aktualisieren oder denselben Auftrag erneut bestätigen.'):e.message;
  }finally{busy.value=false;}
}
function close(){if(!busy.value)emit('close');}
function keyboard(event){if(event.key==='Escape')close();}
onMounted(()=>{closeButton.value?.focus();loadHistory();timer=setInterval(loadHistory,5000);document.addEventListener('keydown',keyboard);});
onUnmounted(()=>{clearInterval(timer);controller?.abort();document.removeEventListener('keydown',keyboard);previousFocus?.focus();});
</script>
<template>
 <div v-if="allowed" class="modal-backdrop" @click.self="close">
  <section class="device-editor mail-replay" role="dialog" aria-modal="true" aria-labelledby="replay-title" :aria-busy="busy">
   <header><h2 id="replay-title">{{t('E-Mail erneut senden')}}</h2><button ref="closeButton" class="refresh" :disabled="busy" @click="close">{{t('Schliessen')}}</button></header>
   <p>{{t('Ereignis')}} #{{event.id}} · {{timestamp(event.created)}} · {{event.device_name??event.device}}</p><p class="replay-original">{{event.message}}</p>
   <p class="form-note">{{t('Einmaliger manueller Versand mit der aktuell gespeicherten E-Mail-Vorlage. Alarmzustand und Bestätigung bleiben erhalten. Automatische Benachrichtigungsfilter gelten hierfür nicht.')}}</p>
   <p v-if="!recipients.length" class="notice">{{t('Bitte zuerst gültige SMTP-Einstellungen und Empfänger speichern.')}}</p>
   <label>{{t('Empfänger')}}<select v-model="recipient" :disabled="busy||!recipients.length"><option v-for="address in recipients" :key="address" :value="address">{{address}}</option></select></label>
   <div v-if="preview" class="mail-preview"><h3>{{t('Betreff')}}</h3><p>{{preview.subject}}</p><h3>{{t('Nachricht')}}</h3><pre>{{preview.body}}</pre></div>
   <p class="form-note">{{t('Ereignis-ID und Ereigniszeit bleiben erhalten. Es wird kein TEST-Zusatz eingefügt. Ein Alarmserver kann identische Ereignisse weiterhin als Duplikate behandeln.')}}</p>
   <p v-if="message" role="status">{{message}}</p><p v-if="error" class="error" role="alert">{{error}}</p>
   <div class="action-row"><button class="refresh" :disabled="busy||!recipient" @click="perform(false)">{{sent?t('Neue Versandvorschau'):t('Versandvorschau erstellen')}}</button><button v-if="preview" class="primary" :disabled="busy||sent" @click="perform(true)">{{t('Einmalig an ausgewählten Empfänger senden')}}</button></div>
   <h3>{{t('Manueller Versandverlauf')}}</h3><p class="form-note">{{t('Bis zu 50 manuelle Sendungen zu diesem Ereignis. SMTP-Annahme bestätigt keine Zustellung im Zielsystem.')}}</p>
   <button class="refresh" :disabled="busy" @click="loadHistory">{{t('Versandverlauf aktualisieren')}}</button>
   <p v-if="!history.length" class="form-note">{{t('Noch keine manuellen Sendungen.')}}</p>
   <ul v-else class="replay-history"><li v-for="job in history" :key="job.id"><strong>{{replayStatus(job)}}</strong><p>{{timestamp(job.queued)}} · {{job.actor}} · {{job.recipient}}</p><p v-if="job.submitted">{{t('SMTP-Annahme:')}} {{timestamp(job.submitted)}}</p><p>{{t('Versuche:')}} {{job.attempts}}<span v-if="job.error"> · {{replayError(job.error)}}</span></p></li></ul>
  </section>
 </div>
</template>
