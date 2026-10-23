<script setup>
import {t} from './i18n.js';
defineProps({security:Object,secret:Object,hasSecret:Boolean,requiredSecret:Boolean});
</script>
<template>
<div class="snmp-security">
<label>{{t('SNMP-Version')}}<select v-model="security.version"><option value="v3">SNMPv3 (authPriv)</option><option value="v2c">SNMPv2c</option><option value="v1">SNMPv1</option></select></label>
<p v-if="security.version!=='v3'" class="form-note">{{t('SNMPv1/v2c übertragen die Community im Klartext und bieten keine kryptografische Integritätsprüfung. Nur in einem entsprechend geschützten Managementnetz verwenden.')}}</p>
<template v-else><div class="form-columns"><label>{{t('SNMPv3-Benutzer')}}<input v-model="security.username" required maxlength="32" autocomplete="off"></label><label>{{t('Authentifizierung')}}<select v-model="security.auth"><option value="sha256">SHA-256</option><option value="sha1">SHA-1</option></select></label></div><p class="form-note">{{t('Verschlüsselung: AES-128. Passphrasen und SHA-Auswahl müssen zum Controller passen. Es wird kein schwächeres Verfahren automatisch versucht.')}}</p></template>
<template v-if="secret"><label>{{t('Zugangsdaten')}}<select v-model="secret.action"><option v-if="hasSecret" value="keep">{{t('Gespeicherte Zugangsdaten beibehalten')}}</option><option value="replace">{{t('Zugangsdaten ersetzen')}}</option><option v-if="!requiredSecret" value="clear">{{t('Gespeicherte Zugangsdaten löschen')}}</option></select><small>{{hasSecret?t('Zugangsdaten sind gespeichert und werden nicht angezeigt.'):t('Noch keine Zugangsdaten gespeichert.')}}</small></label>
<template v-if="secret.action==='replace'"><div v-if="security.version==='v3'" class="form-columns"><label>{{t('Authentifizierungs-Passphrase')}}<input v-model="secret.auth_password" type="password" required minlength="8" maxlength="1024" autocomplete="new-password"></label><label>{{t('Verschlüsselungs-Passphrase')}}<input v-model="secret.priv_password" type="password" required minlength="8" maxlength="1024" autocomplete="new-password"></label></div><label v-else>{{t('Community')}}<input v-model="secret.community" type="password" required maxlength="255" autocomplete="new-password"></label></template>
<p class="form-note">{{t('Nach Änderungen an Ziel, Benutzer, Sicherheitsverfahren, Kontext oder freigegebener Senderidentität Zugangsdaten ausdrücklich ersetzen oder bei deaktivierter Nutzung löschen. Abfrage und Trap-Empfang haben getrennte Zugangsdaten.')}}</p></template>
</div>
</template>
