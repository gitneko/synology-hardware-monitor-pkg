<script setup>
import {t} from './i18n.js';
import {reactive,ref,watch,onUnmounted,toRaw,computed} from 'vue';
import {administer} from './device-api.js';
import {freshWebhook,newField,editWebhook,webhookInput,webhookStatus,webhookError,webhookFormatLabel,jsonTemplate,revealWebhookUrl,defaultChatTemplate,discordEmbedTemplate} from './webhooks.js';
const props=defineProps({dashboard:Object});const emit=defineEmits(['saved']);
const form=reactive(freshWebhook()),editing=ref(false),busy=ref(false),error=ref(''),message=ref(''),preview=ref(null),origin=ref(''),hasCredential=ref(false),urlVisible=ref(false);
const missingDevices=computed(()=>form.settings.devices.filter(id=>!props.dashboard.devices?.some(e=>e.device.id===id)));
const chatTemplate=computed({get:()=>form.settings.chat_template??defaultChatTemplate,set:value=>{form.settings.chat_template=value;}});
const embedsTemplate=computed({get:()=>form.settings.embeds_template??'',set:value=>{form.settings.embeds_template=value||null;}});
const placeholders=['schema_version','event_id','delivery_id','device_id','device','resource','kind','health','message','created','time','source','verified','provisional'];
function open(view){urlVisible.value=false;Object.assign(form,view?editWebhook(view):freshWebhook());origin.value=view?.url_origin??'';hasCredential.value=view?.has_credential??false;editing.value=true;error.value='';message.value='';preview.value=null;}
function load(){const saved=props.dashboard.webhooks?.find(e=>e.id===form.id);if(saved)open(saved);}
watch(()=>props.dashboard.webhooks,(list)=>{const saved=list?.find(e=>e.id===form.id);if(editing.value&&form.id&&!busy.value&&(!saved||saved.revision!==form.revision))error.value=t('Das Webhook-Ziel wurde geändert oder gelöscht. Bitte gespeicherte Angaben neu laden.');});
watch(()=>form.settings.format,(format)=>{preview.value=null;if(format==='json'){try{JSON.parse(form.settings.template);}catch{form.settings.template=jsonTemplate;}}if(!['text','json'].includes(format))form.settings.content_type='';});
// Editing any input invalidates the preview, without mutating the dashboard snapshot.
watch(form,()=>{preview.value=null;},{deep:true});
let controller;onUnmounted(()=>controller?.abort());
async function act(action){
 if(busy.value)return;busy.value=true;error.value='';message.value='';controller=new AbortController();const timeout=setTimeout(()=>controller.abort(),45000);
 try{
  const operation=action==='webhook_delete'?{action,id:form.id,revision:form.revision}:{action,webhook:webhookInput(toRaw(form))};
  const result=await administer(props.dashboard,operation,fetch,controller.signal);
  if(action==='webhook_preview')preview.value=result.preview;
  else if(action==='webhook_test')message.value=t('Testnachricht vom Webhook-Empfänger angenommen.')+` (HTTP ${result.http_status})`;
  else {message.value=t(action==='webhook_delete'?'Webhook-Ziel gelöscht.':'Webhook-Ziel gespeichert. Offene Aufträge dieses Ziels wurden storniert.');editing.value=false;form.url='';form.credential='';for(const field of [...form.settings.fields,...form.settings.headers])if(field.secret)field.value='';emit('saved');}
 }catch(e){error.value=e.name==='AbortError'?t('Zeitüberschreitung. Bitte vor einem erneuten Test den Empfänger prüfen.'):e.message;}
 finally{clearTimeout(timeout);busy.value=false;}
}
async function toggleUrl(){
 if(busy.value)return;
 if(urlVisible.value){urlVisible.value=false;return;}
 if(form.url||!form.id){urlVisible.value=true;return;}
 busy.value=true;error.value='';controller=new AbortController();const timer=setTimeout(()=>controller.abort(),15000);
 try{await revealWebhookUrl(props.dashboard,form,fetch,controller.signal);urlVisible.value=true;}
 catch(e){error.value=e.name==='AbortError'?t('Zeitüberschreitung. Bitte die Ansicht aktualisieren.'):e.message;}
 finally{clearTimeout(timer);busy.value=false;}
}
watch(editing,value=>{if(!value){urlVisible.value=false;form.url='';form.credential='';}});
function removeTarget(view){open(view);if(globalThis.confirm(t('Webhook-Ziel löschen und dessen offene Aufträge stornieren?')))act('webhook_delete');}
</script>
<template><section class="panel device-editor webhook-settings"><header><div><p class="eyebrow">{{t('WEBHOOKS')}}</p><h2>{{t('Ausgehende Webhooks')}}</h2></div><button class="refresh" :disabled="busy" @click="open(null)">{{t('Webhook-Ziel hinzufügen')}}</button></header>
<p>{{t('Eigene HTTP- und HTTPS-Ziele mit unabhängiger Ereignisauswahl. Neue Ziele versenden ausschließlich künftige Ereignisse.')}}</p>
<p v-if="!dashboard.webhooks?.length" class="empty">{{t('Noch keine Webhook-Ziele eingerichtet.')}}</p>
<div v-for="target in dashboard.webhooks" :key="target.id" class="webhook-target">
 <div><strong>{{target.settings.name}}</strong> · {{target.settings.enabled?t('aktiv'):t('inaktiv')}}<br><span>{{target.url_origin}} · {{webhookFormatLabel(target.settings.format)}} · {{t('{0} offene Aufträge',target.pending)}}</span><br><small>{{webhookStatus(target.status)}}<template v-if="target.status?.http_status"> · HTTP {{target.status.http_status}}</template><template v-if="target.status?.error"> · {{webhookError(target.status.error)}}</template></small></div>
 <div class="actions"><button type="button" class="refresh" :disabled="busy" @click="open(target)">{{t('Bearbeiten')}}</button><button type="button" class="refresh" :disabled="busy" @click="removeTarget(target)">{{t('Löschen')}}</button></div>
</div>
<form v-if="editing" @submit.prevent="act('webhook_save')"><fieldset :disabled="busy">
 <div class="form-columns"><label>{{t('Name')}}<input v-model="form.settings.name" required maxlength="120"></label><label>{{t('Sprache der Webhook-Meldungen')}}<select v-model="form.settings.language"><option value="de">Deutsch</option><option value="en">English</option></select></label></div>
 <label class="check"><input v-model="form.settings.enabled" type="checkbox">{{t('Dieses Webhook-Ziel aktivieren')}}</label>
 <label for="webhook-url" class="webhook-url-label">{{t('Webhook-Adresse (HTTP oder HTTPS)')}}</label><div class="webhook-url-row"><input id="webhook-url" v-model="form.url" :type="urlVisible?'text':'password'" autocomplete="new-password" :required="!form.id" :placeholder="form.id?t('Leer lassen, um die gespeicherte Adresse beizubehalten'):t('Vollständige Webhook-URL')" maxlength="8192"><button type="button" class="refresh" aria-controls="webhook-url" :aria-pressed="urlVisible" @click="toggleUrl">{{urlVisible?t('URL verbergen'):t('URL anzeigen')}}</button></div>
 <p v-if="origin" class="form-note">{{t('Gespeichertes Ziel:')}} {{origin}}</p>
 <p class="form-note">{{t('Die vollständige Adresse wird verschlüsselt gespeichert. Bei HTTP werden Nachricht und Zugangsdaten unverschlüsselt übertragen.')}}</p>
 <label class="check"><input v-model="form.settings.allow_private" type="checkbox">{{t('Private und lokale Netzwerkziele für dieses Ziel erlauben')}}</label>
 <label>{{t('Nachrichtenformat')}}<select v-model="form.settings.format"><option value="generic">{{t('Generisches Ereignis-JSON')}}</option><option value="text">{{t('Freier Text')}}</option><option value="json">{{t('Eigenes JSON')}}</option><option value="form">application/x-www-form-urlencoded</option><option value="multipart">multipart/form-data</option><option value="discord">Discord</option><option value="slack">Slack</option></select></label>
 <template v-if="form.settings.format==='discord'"><h3>{{t('Discord-Absender')}}</h3><div class="form-columns"><label>{{t('Absendername (optional)')}}<input v-model="form.settings.discord_username" maxlength="80" autocomplete="off"></label><label>{{t('Avatar-URL (optional)')}}<input v-model="form.settings.discord_avatar_url" type="url" maxlength="2048" placeholder="https://example.com/avatar.png" autocomplete="off" spellcheck="false"></label></div><p class="form-note">{{t('Leer lassen, um Name und Avatar des Discord-Webhooks zu verwenden. Die Avatar-URL muss öffentlich erreichbar sein. Einen eigenen Avatar hochladen kannst du in Discord bei den Webhook-Einstellungen; er gilt dort als Standard für den Webhook.')}}</p></template>
 <p v-if="form.settings.format==='slack'" class="form-note">{{t('Slack-Webhooks verwenden den Namen und das Icon der Slack-App. Beides wird in Slack unter Basic Information → Display Information eingerichtet und kann hier nicht pro Nachricht überschrieben werden. Ein App-Icon kann dort hochgeladen werden; eine URL ist über die separate Slack-App-Konfigurations-API möglich.')}}</p>
 <template v-if="['discord','slack'].includes(form.settings.format)"><label>{{t('Textvorlage für die Chat-Nachricht')}}<textarea v-model="chatTemplate" rows="5" maxlength="65536" spellcheck="false"></textarea></label><button type="button" class="refresh" @click="form.settings.chat_template=null">{{t('Standardtext einsetzen')}}</button><p class="form-note">{{t('Die Vorlage unterstützt die Ereignisplatzhalter unten. Zu lange Nachrichtentexte werden an das gewählte Chat-Format angepasst.')}}</p></template>
 <template v-if="form.settings.format==='discord'"><label class="webhook-embeds">{{t('Discord-Embeds als JSON (optional)')}}<textarea v-model="embedsTemplate" rows="10" maxlength="65536" spellcheck="false" placeholder="[]"></textarea></label><button type="button" class="refresh" @click="form.settings.embeds_template=discordEmbedTemplate">{{t('Embed-Beispiel einsetzen')}}</button><p class="form-note">{{t('JSON-Liste mit bis zu 10 Embeds. Titel, Beschreibung, Farbe, Felder, Zeitstempel, Autor, Fußzeile und Bild-URLs sind möglich. Platzhalter werden sicher eingesetzt; Vorschau und Test prüfen die Discord-Limits. Für reine Embeds kann die Textvorlage leer bleiben.')}}</p></template>
 <template v-if="['text','json'].includes(form.settings.format)"><label>{{t('Nachrichtenvorlage')}}<textarea v-model="form.settings.template" rows="8" maxlength="65536" spellcheck="false"></textarea></label><label>{{t('Abweichender Content-Type (optional)')}}<input v-model="form.settings.content_type" maxlength="200" :placeholder="form.settings.format==='json'?'application/json':'text/plain; charset=utf-8'"></label></template>
 <template v-if="['form','multipart'].includes(form.settings.format)"><h3>{{t('Formularfelder')}}</h3><p class="form-note">{{t('Feldnamen dürfen mehrfach vorkommen. Kodierung und Multipart-Boundary werden automatisch erzeugt. Multipart unterstützt in dieser Version Textfelder.')}}</p>
  <div v-for="(field,index) in form.settings.fields" :key="field.id" class="webhook-field">
   <label>{{t('Feldname')}}<input v-model="field.name" required maxlength="200"></label><label>{{t('Wert oder Vorlage')}}<input v-model="field.value" :type="field.secret?'password':'text'" maxlength="8192" :placeholder="field.secret&&form.id?t('Leer lassen, um den geheimen Wert beizubehalten'):''" autocomplete="new-password"></label>
   <label class="check"><input v-model="field.secret" type="checkbox">{{t('Geheimer, unveränderter Wert')}}</label><label v-if="form.settings.format==='multipart'">{{t('Content-Type des Feldes (optional)')}}<input v-model="field.content_type" maxlength="200"></label><button type="button" class="refresh" @click="form.settings.fields.splice(index,1)">{{t('Entfernen')}}</button>
  </div><button type="button" class="refresh" :disabled="form.settings.fields.length>=64" @click="form.settings.fields.push(newField())">{{t('Feld hinzufügen')}}</button>
 </template>
 <p class="form-note">{{t('Verfügbare Platzhalter:')}} <code v-for="key in placeholders" :key="key" v-text="'{{'+key+'}} '"></code></p>
 <p v-if="form.settings.format==='json'" class="form-note">{{t('Ein JSON-String, der nur einen Platzhalter enthält, übernimmt dessen Datentyp. Beispiel:')}} <code>"event_id": "&#123;&#123;event_id&#125;&#125;"</code></p>
 <h3>{{t('Authentifizierung und Header')}}</h3><label>{{t('Authentifizierung')}}<select v-model="form.settings.auth"><option value="none">{{t('Keine')}}</option><option value="bearer">Bearer Token</option><option value="basic">Basic Auth</option></select></label>
 <label v-if="form.settings.auth==='basic'">{{t('Benutzername')}}<input v-model="form.settings.username" autocomplete="off" maxlength="256"></label>
 <label v-if="form.settings.auth!=='none'">{{t('Token oder Passwort')}}<input v-model="form.credential" type="password" autocomplete="new-password" maxlength="4096" :placeholder="hasCredential?t('Leer lassen, um den geheimen Wert beizubehalten'):''"></label>
 <div v-for="(field,index) in form.settings.headers" :key="field.id" class="webhook-field"><label>{{t('Headername')}}<input v-model="field.name" required maxlength="200"></label><label>{{t('Headerwert')}}<input v-model="field.value" :type="field.secret?'password':'text'" autocomplete="new-password" maxlength="8192" :placeholder="field.secret&&form.id?t('Leer lassen, um den geheimen Wert beizubehalten'):''"></label><label class="check"><input v-model="field.secret" type="checkbox">{{t('Geheimer, unveränderter Wert')}}</label><button type="button" class="refresh" @click="form.settings.headers.splice(index,1)">{{t('Entfernen')}}</button></div>
 <button type="button" class="refresh" :disabled="form.settings.headers.length>=32" @click="form.settings.headers.push(newField())">{{t('Header hinzufügen')}}</button>
 <label class="webhook-ca">{{t('Eigene CA-Zertifikate für HTTPS (optional)')}}<textarea v-model="form.settings.ca_pem" rows="3" maxlength="65536" spellcheck="false"></textarea></label>
 <h3>{{t('Ereignisauswahl dieses Ziels')}}</h3><label v-for="[key,title] in [['critical',t('Kritische Ereignisse')],['warning',t('Warnungen')],['recovery',t('Entwarnungen')],['repeat',t('Alarmwiederholungen')],['monitoring',t('Abfragewarnungen')],['hardware_log',t('Neue Hardwarelog-Ereignisse')],['snmp_trap',t('Verifizierte SNMP-Trap-Ereignisse ohne Komponentenzuordnung')]]" :key="key" class="check"><input v-model="form.settings.selection[key]" type="checkbox">{{title}}</label>
 <p class="form-note">{{t('Geräteoptionen, Alarmbestätigungen und Ereignisbündelung gelten auch für Webhooks. Die Filter für E-Mail und DSM-Desktop beeinflussen dieses Ziel nicht.')}}</p>
 <h3>{{t('Gerätefilter')}}</h3><p class="form-note">{{t('Ohne Auswahl werden alle Geräte berücksichtigt.')}}</p><label v-for="entry in dashboard.devices" :key="entry.device.id" class="check"><input v-model="form.settings.devices" type="checkbox" :value="entry.device.id">{{entry.device.name}}</label>
 <label v-for="id in missingDevices" :key="id" class="check"><input v-model="form.settings.devices" type="checkbox" :value="id">{{t('Entferntes Gerät:')}} {{id}}</label>
 <div class="actions"><button type="button" class="refresh" @click="act('webhook_preview')">{{t('Vorschau prüfen')}}</button><button type="button" class="refresh" @click="act('webhook_test')">{{t('Testnachricht senden')}}</button><button v-if="form.id" type="button" class="refresh" @click="load">{{t('Gespeicherte Angaben laden')}}</button></div>
 <p class="form-note">{{t('Testnachrichten verwenden Beispieldaten und senden auch an ein deaktiviertes Ziel. Zwischen Tests mindestens 30 Sekunden warten.')}}</p>
</fieldset>
<div v-if="preview" class="webhook-preview"><strong>{{preview.content_type}}</strong><pre>{{preview.body}}</pre></div>
<footer><button class="primary" :disabled="busy">{{busy?t('Wird gespeichert …'):t('Webhook-Ziel speichern')}}</button><button type="button" class="refresh" :disabled="busy" @click="editing=false">{{t('Abbrechen')}}</button></footer>
</form><div v-if="error" class="error" role="alert">{{error}}</div><div v-if="message" class="notice" role="status">{{message}}</div></section></template>
