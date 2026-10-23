<script setup>
import {t} from './i18n.js';
import {reactive,ref,watch,onUnmounted} from 'vue';
import {administer} from './device-api.js';
import {mailInput} from './mail-settings.js';
const props=defineProps({dashboard:Object});const emit=defineEmits(['saved']);
const form=reactive({}),revision=ref(0),busy=ref(false),error=ref(''),message=ref(''),preview=ref(null);
function load(){error.value='';message.value='';preview.value=null;const saved=props.dashboard.mail;revision.value=saved.revision;Object.assign(form,saved.settings,{authentication:Boolean(saved.settings.username)||saved.revision===0,language:saved.settings.language??'de',recipients:saved.settings.recipients.join('\n'),ca_pem:saved.settings.ca_pem??'',password:''});}
load();watch(()=>props.dashboard.mail?.revision,(value)=>{if(value!==revision.value && !busy.value)error.value=t("Gespeicherte Einstellungen wurden geändert. Bitte die aktuellen Angaben laden, bevor du speicherst.");});
let controller;onUnmounted(()=>{controller?.abort();form.password='';});
watch(form,()=>{preview.value=null;});
async function run(action){
 if(busy.value)return;busy.value=true;error.value='';message.value='';controller=new AbortController();const timer=setTimeout(()=>controller.abort(),24000);
 try{const result=await administer(props.dashboard,{action,mail:mailInput(form,revision.value)},fetch,controller.signal);
  if(action==='mail_preview')preview.value=result.preview;
  else if(action==='mail_save'){form.password='';revision.value=result.revision;message.value=t("Einstellungen gespeichert. Bisherige offene E-Mail-Aufträge wurden storniert.");emit('saved');}
  else message.value=result.message;
 }catch(e){error.value=e.name==='AbortError'?t("Zeitüberschreitung. Vor einer erneuten Testmail das Postfach prüfen."):e.message;}
 finally{clearTimeout(timer);busy.value=false;}
}
function defaults(){form.subject_template='[Hardware Monitor] {{health}} – {{device}}';form.body_template=form.language==='en'?'{{message}}\n\nDevice: {{device}}\nState: {{health}}\nType: {{kind}}\nTime: {{time}}\nEvent: {{event_id}}\nComponent: {{resource}}\n':'{{message}}\n\nGerät: {{device}}\nZustand: {{health}}\nArt: {{kind}}\nZeit: {{time}}\nEreignis: {{event_id}}\nKomponente: {{resource}}\n';}
</script>
<template>
<section class="panel mail-settings device-editor">
 <header><div><p class="eyebrow">{{t("BENACHRICHTIGUNGEN")}}</p><h2>{{t("E-Mail-Versand")}}</h2><button type="button" class="refresh" :disabled="busy" @click="load">{{t("Gespeicherte Angaben laden")}}</button><p class="form-note">{{t("Versand über deinen SMTP-Server. Ein eigener SMTP-Server wird auf dem NAS nicht betrieben.")}}</p></div></header>
 <form @submit.prevent="run('mail_save')"><fieldset :disabled="busy">
 <label class="check"><input v-model="form.enabled" type="checkbox">{{t("Automatische E-Mails aktivieren")}}</label>
 <p class="form-note">{{t("Gilt für künftige ausgewählte Ereignisse der Geräte mit aktivierter Benachrichtigungsoption. Bisherige Meldungen werden nicht nachgesendet. Beim Speichern werden noch offene E-Mail-Aufträge storniert; bereits angenommene E-Mails können nicht zurückgerufen werden.")}}</p>
 <div class="form-columns"><label>{{t('SMTP-Server')}}<input v-model="form.host" required placeholder="smtp.example.com" autocomplete="off"><small>{{t("Hostname oder IP-Adresse, ohne https:// und ohne Port.")}}</small></label><label>Port<input v-model="form.port" type="number" required min="1" max="65535"></label></div>
 <label>{{t("Verschlüsselung")}}<select v-model="form.security"><option value="starttls">{{t("STARTTLS erforderlich (üblicherweise Port 587)")}}</option><option value="tls">{{t("TLS ab Verbindungsaufbau (üblicherweise Port 465)")}}</option><option value="plain">{{t("Unverschlüsselt, ohne STARTTLS (z. B. Port 25)")}}</option></select><small v-if="form.security!=='plain'">{{t("Zertifikat und Servername werden geprüft; kein automatischer Rückfall auf unverschlüsselten Versand.")}}</small><small v-else>{{t("Nachrichten und gegebenenfalls SMTP-Zugangsdaten werden unverschlüsselt übertragen. Für diesen Modus z. B. Port 25 einstellen.")}}</small></label>
 <label class="check"><input v-model="form.authentication" type="checkbox">{{t("SMTP-Anmeldung verwenden")}}</label>
 <div v-if="form.authentication" class="form-columns"><label>{{t("SMTP-Benutzer")}}<input v-model="form.username" required maxlength="256" autocomplete="off"></label><label>{{t("SMTP-Passwort")}}<input v-model="form.password" type="password" :required="!dashboard.mail.has_password" maxlength="4096" autocomplete="new-password"><small>{{t("Leer lassen, um das gespeicherte Passwort zu behalten. Bei Änderung von Server, Port, TLS-Modus oder Benutzer erneut eingeben. App-Passwörter werden unterstützt; OAuth-Anmeldung ist noch nicht verfügbar.")}}</small></label></div>
 <div class="form-columns"><label>{{t("Absenderadresse")}}<input v-model="form.from_address" type="email" required placeholder="monitor@example.com"></label><label>{{t("Absendername")}}<input v-model="form.from_name" maxlength="128"></label></div>
 <label>{{t("Empfänger")}}<textarea v-model="form.recipients" rows="3" required :placeholder="t(&quot;betrieb@example.com&quot;)"></textarea><small>{{t("Bis zu 20 Adressen, getrennt durch Zeilen, Leerzeichen, Komma oder Semikolon. Jede Nachricht wird einzeln adressiert.")}}</small></label>
 <details v-if="form.security!=='plain'"><summary>{{t("Eigene Zertifizierungsstelle")}}</summary><label>{{t("Zusätzliches CA-Zertifikat (PEM)")}}<textarea v-model="form.ca_pem" rows="4" maxlength="65536" spellcheck="false"></textarea><small>{{t("Optional für interne SMTP-Server. Nur Zertifikate, keine privaten Schlüssel.")}}</small></label></details>
 <label>{{t('Sprache der E-Mail-Meldungen')}}<select v-model="form.language"><option value="de">Deutsch</option><option value="en">English</option></select></label><p class="form-note">{{t('Standardsprache für neue Vorlagen und Meldungstexte. Eigene Vorlagen und Hardwarelogs bleiben unverändert.')}}</p><button type="button" class="refresh" :disabled="busy" @click="defaults">{{t('Standardvorlage einsetzen')}}</button><h3>{{t("E-Mail-Vorlage")}}</h3><p class="form-note">{{t("Platzhalter:")}} <span v-pre>{{device}}, {{health}}, {{kind}}, {{message}}, {{time}}, {{time_local}}, {{time_utc}}, {{timezone}}, {{event_id}}, {{resource}}, {{source}}, {{verified}}, {{provisional}}</span>{{t(". Die Vorlage gilt für alle ausgewählten Ereignisarten. Zeit und Entstehung entsprechen dem Ereignis, auch bei späteren Versandversuchen.")}}</p>
 <div class="form-columns"><label>{{t("Zeitzone")}}<input v-model="form.timezone" required list="mail-timezones" maxlength="64" placeholder="Europe/Zurich"><datalist id="mail-timezones"><option>Europe/Zurich</option><option>Europe/Berlin</option><option>Europe/Vienna</option><option>UTC</option></datalist><small>{{t("IANA-Zeitzone; Sommer-/Winterzeit wird berücksichtigt.")}}</small></label><label>{{t("Zeitformat")}}<select v-model="form.date_format"><option value="%d.%m.%Y %H:%M:%S">{{t("Deutsch: 18.10.2026 14:30:00")}}</option><option value="%Y-%m-%d %H:%M:%S %:z">{{t("ISO mit UTC-Abweichung")}}</option><option v-if="!['%d.%m.%Y %H:%M:%S','%Y-%m-%d %H:%M:%S %:z'].includes(form.date_format)" :value="form.date_format">{{t("Eigenes Format")}}</option></select></label></div>
 <label>{{t("Format anpassen")}}<input v-model="form.date_format" required maxlength="120"><small>{{t("%d Tag, %m Monat, %Y Jahr, %H Stunde, %M Minute, %S Sekunde, %:z UTC-Abweichung.")}} <span v-text="t('{{time}} und {{time_local}}')"></span> {{t("nutzen diese Einstellungen;")}} <span v-pre>{{time_utc}}</span> {{t("bleibt UTC im ISO-Format.")}}</small></label>
 <label>{{t("Betreff")}}<input v-model="form.subject_template" required maxlength="500"></label>
 <label>{{t("Nachricht (Text)")}}<textarea v-model="form.body_template" rows="9" required maxlength="16384" spellcheck="false"></textarea></label>
 </fieldset>
 <div v-if="error" class="error" role="alert">{{error}}</div><div v-if="message" class="notice" role="status">{{message}}</div>
 <div v-if="preview" class="mail-preview"><h3>{{preview.subject}}</h3><pre>{{preview.body}}</pre></div>
 <footer><button type="button" class="refresh" :disabled="busy" @click="run('mail_preview')">{{t("Vorlage ansehen")}}</button><button type="button" class="refresh" :disabled="busy" @click="run('mail_test')">{{t("Testmail an erste Empfängeradresse senden")}}</button><button class="primary" type="submit" :disabled="busy">{{busy?t("Wird ausgeführt …"):t("Speichern")}}</button></footer>
 <p class="form-note">{{t("Vorschau und Testmail nutzen die aktuellen Eingaben. Eine Testmail ist auch bei deaktiviertem automatischem Versand möglich. „Vom SMTP-Server angenommen“ bestätigt keine Zustellung ins Postfach.")}}</p>
 </form>
</section>
</template>
