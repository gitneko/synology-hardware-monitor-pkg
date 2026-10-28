import {t} from './i18n.js';
import {administer} from './device-api.js';
export function rowId(){return globalThis.crypto.randomUUID().replaceAll('-','');}
export function newField(){return {id:rowId(),name:'',value:'',secret:false,content_type:''};}
export const jsonTemplate=JSON.stringify({event_id:'{{event_id}}',device:'{{device}}',health:'{{health}}',message:'{{message}}',verified:'{{verified}}'},null,2);
export const defaultChatTemplate='[{{health}}] {{message}}';
export const discordEmbedTemplate=JSON.stringify([{title:'{{device}}',description:'{{message}}',color:15548997,fields:[{name:'Zustand',value:'{{health}}',inline:true},{name:'Komponente',value:'{{resource}}',inline:true}],timestamp:'{{time}}'}],null,2);
export function freshWebhook(){return {id:null,revision:0,url:'',credential:'',settings:{name:'',enabled:false,language:'de',format:'generic',template:'{{message}}',chat_template:null,embeds_template:null,discord_username:'',discord_avatar_url:'',fields:[],headers:[],auth:'none',username:'',allow_private:false,ca_pem:'',content_type:'',devices:[],selection:{critical:true,warning:true,recovery:true,repeat:true,hardware_log:true,snmp_trap:false,monitoring:true}}};}
export function editWebhook(view){return {...freshWebhook(),id:view.id,revision:view.revision,settings:{...freshWebhook().settings,...JSON.parse(JSON.stringify(view.settings))}};}
export function webhookInput(form){return {id:form.id,revision:form.revision,url:form.url||null,credential:form.credential||null,settings:JSON.parse(JSON.stringify(form.settings))};}
export function webhookStatus(job){
 if(!job)return t('Noch kein automatischer Versand');
 if(job.delivered)return t('Vom Empfänger angenommen');
 if(job.cancelled&&job.error==='device_filtered')return t('durch Geräteauswahl ausgeschlossen');
 if(job.cancelled&&job.error==='filtered')return t('durch Ereignisauswahl ausgeschlossen');
 if(job.cancelled)return t('Storniert');
 if(job.permanent)return t('Fehlgeschlagen');
 return job.error?t('Erneuter Versuch vorgemerkt'):t('Vorgemerkt');
}
export function webhookDeliveryText(event){return (event.webhooks??[]).map(job=>`${job.name}: ${webhookStatus(job)}${job.http_status?` (HTTP ${job.http_status})`:''}`).join(' · ');}

export function webhookError(code){return ({
 webhook_timeout:t('Zeitlimit überschritten'),webhook_connection_failed:t('Verbindung fehlgeschlagen'),webhook_http_error:t('Vom Empfänger abgewiesen'),webhook_network_blocked:t('Netzwerkziel gesperrt'),webhook_config_invalid:t('Ungültige Konfiguration'),webhook_discord_invalid:t('Ungültige Discord-Embeds'),webhook_response_large:t('Antwort zu groß'),expired:t('Auftrag abgelaufen'),queue_full:t('Versandwarteschlange voll'),configuration_changed:t('Zielkonfiguration geändert'),target_deleted:t('Ziel gelöscht'),acknowledged:t('Alarm bestätigt'),reset:t('Alarm zurückgesetzt'),log_reading_disabled:t('Log-Abfrage deaktiviert'),query_superseded:t('Durch aktuelle Abfrage ersetzt'),cancelled:t('Storniert')})[code]??t('Versand fehlgeschlagen');}

export async function revealWebhookUrl(dashboard,form,request=fetch,signal){
 if(form.url||!form.id)return form.url;
 const id=form.id,revision=form.revision;
 const result=await administer(dashboard,{action:'webhook_reveal_url',id,revision},request,signal);
 if(form.id!==id||form.revision!==revision)throw new Error(t('Das Webhook-Ziel wurde geändert oder gelöscht. Bitte gespeicherte Angaben neu laden.'));
 if(!form.url)form.url=result.url;
 return form.url;
}

export function webhookFormatLabel(format){return ({generic:t('Generisches Ereignis-JSON'),text:t('Freier Text'),json:t('Eigenes JSON'),form:'application/x-www-form-urlencoded',multipart:'multipart/form-data',discord:'Discord',slack:'Slack'})[format]??format;}
