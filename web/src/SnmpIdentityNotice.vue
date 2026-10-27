<script setup>
import {t} from './i18n.js';
import {needsTrapIdentity} from './snmp.js';
defineProps({entry:Object});
defineEmits(['verify']);
</script>
<template>
<section v-if="needsTrapIdentity(entry)" class="notice" role="alert">
  <strong>{{t('Gespeichert – SNMPv3-Trap-Empfang noch gesperrt.')}}</strong>
  <p>{{entry.device.name}} · {{t('Prüfe die Senderidentität, übernimm die geprüfte Engine-ID und speichere die Freigabe.')}}</p>
  <p v-if="!entry.device.snmp_poll">{{t('Hinterlege dafür zuerst ein SNMP-Abfrageziel für die Senderprüfung im Gerät.')}}</p>
  <button type="button" class="primary" @click="$emit('verify',entry)">{{entry.device.snmp_poll?t('Senderidentität prüfen'):t('Senderprüfung einrichten')}}</button>
</section>
</template>
