<script setup>
import {t} from './i18n.js';
import {reactive,ref,watch,onUnmounted} from 'vue';
import {administer} from './device-api.js';
const props=defineProps({dashboard:Object});const emit=defineEmits(['saved']);
const form=reactive({language:'de',desktop_enabled:false,selection:{}}),revision=ref(0),busy=ref(false),error=ref(''),message=ref('');
function load(){const saved=props.dashboard.notification_settings;form.language=saved.settings.language??'de';form.desktop_enabled=saved.settings.desktop_enabled;form.selection={...saved.settings.selection};revision.value=saved.revision;error.value='';message.value='';}
load();watch(()=>props.dashboard.notification_settings?.revision,(value)=>{if(value!==revision.value&&!busy.value)error.value=t("Einstellungen wurden geändert. Bitte die gespeicherten Angaben laden.");});
let controller;onUnmounted(()=>controller?.abort());
async function save(){if(busy.value)return;busy.value=true;error.value='';message.value='';controller=new AbortController();const timer=setTimeout(()=>controller.abort(),24000);
 try{const result=await administer(props.dashboard,{action:'notification_save',settings:{revision:revision.value,language:form.language,desktop_enabled:form.desktop_enabled,selection:{...form.selection}}},fetch,controller.signal);revision.value=result.revision;message.value=t("Benachrichtigungseinstellungen gespeichert. Offene Versandaufträge wurden storniert.");emit('saved');}
 catch(e){error.value=e.name==='AbortError'?t("Zeitüberschreitung. Bitte die Ansicht aktualisieren."):e.message;}finally{clearTimeout(timer);busy.value=false;}}
</script>
<template><section class="panel device-editor notification-settings"><header><div><p class="eyebrow">{{t("BENACHRICHTIGUNGEN")}}</p><h2>{{t("Kanäle & Ereignisse")}}</h2><button class="refresh" :disabled="busy" @click="load">{{t("Gespeicherte Angaben laden")}}</button></div></header>
<form @submit.prevent="save"><fieldset :disabled="busy">
<p>{{t("Beim Gerät muss „Benachrichtigungen für dieses Gerät aktivieren“ eingeschaltet sein. Die folgenden Filter gelten gemeinsam für E-Mail und DSM-Desktop.")}}</p>
<label class="check"><input v-model="form.desktop_enabled" type="checkbox">{{t("Automatische DSM-Desktopmeldungen aktivieren")}}</label>
<p class="form-note">{{t("Beim Speichern wird dein angemeldeter DSM-Benutzer")}} {{dashboard.user.name}} {{t("als Empfänger gesetzt. Aktuell gespeichert:")}} {{dashboard.notification_settings.settings.desktop_recipient??t("kein Empfänger")}}{{t(". E-Mail wird unabhängig davon unten eingerichtet.")}}</p>
<p class="form-note">{{t("Die Desktopmeldung enthält Gerät und Meldung. Die Ereignisnummer verweist auf den Eintrag in Hardware Monitor.")}}</p>
<label>{{t('Sprache der Desktopmeldungen')}}<select v-model="form.language"><option value="de">Deutsch</option><option value="en">English</option></select></label><p class="form-note">{{t('Die Hintergrundkanäle verwenden diese gespeicherte Sprache, unabhängig von der Oberflächensprache.')}}</p><h3>{{t("Ereignisauswahl")}}</h3>
<label v-for="[key,title] in [['critical',t(&quot;Kritische Ereignisse&quot;)],['warning',t(&quot;Warnungen&quot;)],['recovery',t(&quot;Entwarnungen&quot;)],['repeat',t(&quot;Alarmwiederholungen&quot;)],['hardware_log',t(&quot;Neue Hardwarelog-Ereignisse&quot;)]]" :key="key" class="check"><input v-model="form.selection[key]" type="checkbox">{{title}}</label>
<p class="form-note">{{t("Wiederholungen und Hardwarelogs benötigen zusätzlich den passenden Schweregrad. Entwarnungen sind separat wählbar. Wiederholungsintervall und Geräteoption werden am Gerät eingestellt. Alle Ereignisse bleiben unabhängig von der Auswahl lokal sichtbar.")}}</p>
</fieldset><div v-if="error" class="error" role="alert">{{error}}</div><div v-if="message" class="notice" role="status">{{message}}</div><footer><button class="primary" :disabled="busy">{{busy?t("Wird gespeichert …"):t("Kanäle & Ereignisse speichern")}}</button></footer><p class="form-note">{{t("Änderungen gelten für künftige Ereignisse. Offene Aufträge beider Kanäle werden beim Speichern storniert; alte Meldungen werden nicht nachgesendet.")}}</p></form></section></template>
