import {t} from './i18n.js';
import {administer} from './device-api.js';
export const uploadChunkSize=512*1024;
function pause(signal){return new Promise((resolve,reject)=>{
 const abort=()=>{clearTimeout(timer);reject(new DOMException('Aborted','AbortError'));};
 const timer=setTimeout(()=>{signal?.removeEventListener('abort',abort);resolve();},700);
 if(signal?.aborted)abort();else signal?.addEventListener('abort',abort,{once:true});
});}
export async function waitJob(dashboard,id,{signal,onProgress=()=>{},request=fetch}={}){
 for(;;){
  const {status}=await administer(typeof dashboard==='function'?dashboard():dashboard,{action:'job_status',id},request,signal);onProgress(status);
  if(status.state==='ready')return status.result;
  if(status.state==='failed'||status.state==='cancelled')throw new Error(status.error||status.code);
  await pause(signal);
 }
}
export function encodeChunk(bytes){
 const parts=[];for(let offset=0;offset<bytes.length;offset+=32768)parts.push(String.fromCharCode(...bytes.subarray(offset,offset+32768)));
 return btoa(parts.join(''));
}
export async function uploadFile(dashboard,id,file,{signal,onProgress=()=>{},request=fetch}={}){
 let offset=0;
 while(offset<file.size){
  const bytes=new Uint8Array(await file.slice(offset,offset+uploadChunkSize).arrayBuffer());
  const operation={action:'backup_upload_part',id,offset,data:encodeChunk(bytes)};
  let result;
  for(let attempt=0;;attempt++){
   try{result=await administer(typeof dashboard==='function'?dashboard():dashboard,operation,request,signal);break;}
   catch(error){if(attempt>=2||signal?.aborted)throw error;await pause(signal);}
  }
  if(result.bytes!==offset+bytes.length)throw new Error(t("Der Upload wurde nicht bestätigt. Bitte erneut prüfen."));
  offset=result.bytes;onProgress(offset);
 }
}
