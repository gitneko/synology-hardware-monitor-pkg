import {t} from './i18n.js';
import {dsmHeaders} from './dsm-session.js';
export async function administer(dashboard,operation,request=fetch,signal) {
  if(dashboard?.user?.role!=='administrator' || !dashboard.csrf) throw new Error(t("Bitte als DSM-Administrator anmelden und die Ansicht aktualisieren."));
  const headers=await dsmHeaders(request,signal);
  const response=await request('./api.cgi',{
    method:'POST',credentials:'same-origin',cache:'no-store',redirect:'error',signal,
    headers:{...headers,'Content-Type':'application/json'},
    body:JSON.stringify({csrf:dashboard.csrf,operation}),
  });
  let body;
  try{body=await response.json();}catch{throw new Error(t("DSM hat keine gültige Antwort geliefert. Bitte aktualisieren und erneut versuchen."));}
  if(!response.ok || body.ok!==true){const error=new Error(body.error||t("Die Änderung wurde nicht bestätigt. Bitte aktualisieren."));error.code=body.code;throw error;}
  return body;
}
