import {t} from './i18n.js';
import {dsmHeaders} from './dsm-session.js';
export const backupFilename='HardwareMonitor-backup.hmbackup';
function nativeDownload(url,filename){
 const anchor=document.createElement('a');
 anchor.href=url;anchor.download=filename;anchor.rel='noreferrer';anchor.referrerPolicy='no-referrer';
 document.body.append(anchor);try{anchor.click();}finally{anchor.remove();}
}
// Check authentication and attachment headers without reading/buffering the file.
// Browser navigation cannot set X-SYNO-TOKEN, so only that navigation uses DSM's
// SynoToken query parameter. Never add a password or session ID to this URL.
export async function downloadBackup(id,{request=fetch,signal,save=nativeDownload}={}){
 if(!/^[a-f0-9]{32}$/i.test(id))throw new Error(t("Der Sicherungsauftrag ist ungültig. Bitte eine neue Sicherung erstellen."));
 let headers;
 try{headers=await dsmHeaders(request,signal);}
 catch(error){if(error.name==='AbortError')throw error;throw new Error(t("Die DSM-Sitzung konnte nicht geprüft werden. Bitte erneut anmelden."));}
 const url='./api.cgi?download='+encodeURIComponent(id);
 let response;
 try{response=await request(url,{method:'HEAD',headers,credentials:'same-origin',cache:'no-store',redirect:'error',signal});}
 catch(error){if(error.name==='AbortError')throw error;throw new Error(t("Der Download konnte nicht geprüft werden. Bitte erneut versuchen."));}
 const type=response.headers?.get('content-type')?.split(';')[0].trim().toLowerCase();
 const disposition=response.headers?.get('content-disposition')??'';
 const length=response.headers?.get('content-length');
 if(!response.ok||type!=='application/octet-stream'||!/^attachment(?:\s*;|$)/i.test(disposition)||(length!==null&&length!==undefined&&!/^[1-9][0-9]*$/.test(length))){
  throw new Error(t("Die Sicherungsdatei ist nicht abrufbar (HTTP {0}). Bitte DSM-Anmeldung und fertigen Sicherungsauftrag prüfen.",response.status??0));
 }
 const token=headers['X-SYNO-TOKEN'];
 const target=token?url+'&SynoToken='+encodeURIComponent(token):url;
 save(target,backupFilename);
}
