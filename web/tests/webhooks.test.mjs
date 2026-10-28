import test from 'node:test';
import assert from 'node:assert/strict';
import {fileURLToPath} from 'node:url';
import {reactive,createSSRApp} from 'vue';
import {renderToString} from '@vue/server-renderer';
import {createServer} from 'vite';
import {freshWebhook,newField,editWebhook,webhookInput,webhookStatus,webhookDeliveryText,revealWebhookUrl,defaultChatTemplate,discordEmbedTemplate} from '../src/webhooks.js';

test('webhook editing retains redacted secrets and supports repeated form field names without changing the dashboard',()=>{
 const settings=freshWebhook().settings;settings.name='Synthetic endpoint';settings.format='multipart';
 settings.fields=[{...newField(),name:'item',value:'{{message}}'},{...newField(),name:'item',value:'',secret:true}];
 const source={id:'a'.repeat(32),revision:2,settings};const saved=structuredClone(source);
 const form=reactive(editWebhook(reactive(source)));form.settings.name='Changed';
 let body=webhookInput(form);assert.equal(body.url,null);assert.equal(body.credential,null);assert.equal(body.settings.fields[1].value,'');assert.notEqual(body.settings.fields[0].id,body.settings.fields[1].id);
 form.url='http://localhost/synthetic';form.credential='synthetic-marker';body=webhookInput(form);assert.equal(body.url,form.url);assert.equal(body.credential,form.credential);assert.deepEqual(source,saved);
});
test('webhook delivery state distinguishes acceptance, cancellation, terminal errors and retry',()=>{
 assert.match(webhookStatus({delivered:123,permanent:true}),/angenommen/);assert.equal(webhookStatus({cancelled:true}),'Storniert');assert.equal(webhookStatus({permanent:true}),'Fehlgeschlagen');assert.match(webhookStatus({error:'timeout'}),/Erneuter Versuch/);
 assert.match(webhookDeliveryText({webhooks:[{name:'Target',http_status:429,error:'rate_limit'}]}),/Target.*429/);
});
test('webhook settings render redacted targets and per-destination status without exposing request credentials',async()=>{
 const server=await createServer({root:fileURLToPath(new URL('..',import.meta.url)),configFile:fileURLToPath(new URL('../vite.config.js',import.meta.url)),optimizeDeps:{noDiscovery:true,include:[]},server:{middlewareMode:true},appType:'custom'});
 try {
  const {default:Settings}=await server.ssrLoadModule('/src/WebhookSettings.vue');
  const html=await renderToString(createSSRApp(Settings,{dashboard:{devices:[],webhooks:[{id:'a'.repeat(32),revision:1,url_origin:'https://hooks.example',settings:{...freshWebhook().settings,name:'Synthetic destination'},pending:2,status:{error:'webhook_http_error',http_status:429}}]}}));
  assert.match(html,/Synthetic destination/);assert.match(html,/https:\/\/hooks.example/);assert.match(html,/2 offene Aufträge/);assert.match(html,/HTTP 429/);assert.match(html,/Webhook-Ziel hinzufügen/);
 } finally {await server.close();}
});

test('saved URLs are explicitly fetched with a revision and never overwrite an entered URL or a different editor',async()=>{
 const dashboard={user:{role:'administrator'},csrf:'synthetic-csrf'};
 const form={id:'a'.repeat(32),revision:3,url:''};let calls=0;
 const mock=async(url,options)=>{
  if(url==='/webman/login.cgi')return {ok:true,json:async()=>({success:true,SynoToken:'synthetic-token'})};
  calls++;const body=JSON.parse(options.body);assert.deepEqual(body.operation,{action:'webhook_reveal_url',id:form.id,revision:3});assert.equal(body.csrf,dashboard.csrf);
  return {ok:true,json:async()=>({ok:true,url:'https://hooks.example/synthetic-path-secret'})};
 };
 assert.equal(await revealWebhookUrl(dashboard,form,mock), 'https://hooks.example/synthetic-path-secret');assert.equal(calls,1);
 form.url='https://new.example/entered';await revealWebhookUrl(dashboard,form,mock);assert.equal(calls,1);assert.equal(form.url,'https://new.example/entered');
 form.url='';let finish;const pending=revealWebhookUrl(dashboard,form,async(url)=>url==='/webman/login.cgi'?{ok:true,json:async()=>({success:true})}:new Promise(resolve=>{finish=resolve;}));
 while(!finish)await new Promise(resolve=>setImmediate(resolve));form.id='b'.repeat(32);finish({ok:true,json:async()=>({ok:true,url:'https://old.example/secret'})});await assert.rejects(pending,/geändert/);assert.equal(form.url,'');
});

test('chat defaults remain optional while custom text and Discord embeds survive editing and saving',()=>{
 const legacy={id:'c'.repeat(32),revision:1,settings:{name:'Legacy Discord',format:'discord'}};
 const editor=editWebhook(legacy);assert.equal(editor.settings.chat_template,null);assert.equal(editor.settings.embeds_template,null);assert.equal(defaultChatTemplate,'[{{health}}] {{message}}');
 editor.settings.chat_template='';editor.settings.embeds_template=discordEmbedTemplate;
 const payload=webhookInput(editor);assert.equal(payload.settings.chat_template,'');assert.equal(JSON.parse(payload.settings.embeds_template)[0].description,'{{message}}');assert.equal(legacy.settings.chat_template,undefined);
});

test('Discord identity editing preserves values and keeps Basic Auth username separate',()=>{
 const legacy=editWebhook({id:'d'.repeat(32),revision:1,settings:{name:'Legacy',format:'discord',username:'basic-user'}});
 assert.equal(legacy.settings.discord_username,'');assert.equal(legacy.settings.discord_avatar_url,'');legacy.settings.discord_username='Hardware Monitor';legacy.settings.discord_avatar_url='https://example.invalid/avatar.png';
 const payload=webhookInput(legacy);assert.equal(payload.settings.discord_username,'Hardware Monitor');assert.equal(payload.settings.discord_avatar_url,'https://example.invalid/avatar.png');assert.equal(payload.settings.username,'basic-user');
});
