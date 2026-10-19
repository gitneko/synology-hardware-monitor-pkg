import {t} from './i18n.js';
export function acknowledgementOperation(device,alarm,acknowledged,reason='') {
  if (!alarm.assessment?.token || alarm.assessment.derived || alarm.key==='collector' || alarm.key.startsWith('coverage:') || alarm.key.startsWith('log:')) throw new Error(t('Bitte einen eigenständigen Hardwarealarm oder seine konkrete Ursache auswählen.'));
  reason=reason.trim();
  if(acknowledged && (!reason || new TextEncoder().encode(reason).length>1000 || /\p{Cc}/u.test(reason))) throw new Error(t('Bitte eine Begründung mit höchstens 1000 UTF-8-Bytes ohne Steuerzeichen angeben.'));
  return {action:'alarm_acknowledge',id:device.device.id,revision:device.revision,key:alarm.key,token:alarm.assessment.token,acknowledged,reason:acknowledged?reason:''};
}
