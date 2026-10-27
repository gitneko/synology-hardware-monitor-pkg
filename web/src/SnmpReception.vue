<script setup>
import {computed} from 'vue';
import {t} from './i18n.js';
import {timestamp} from './health.js';
const props=defineProps({entry:Object,sender:Object,compact:Boolean});
// The hint belongs to the live configuration, while accepted receipts may
// include history from an older revision or a restored backup.
const hint=computed(()=>props.sender?.revision===props.entry?.revision?props.sender?.last_poll_hint:null);
const accepted=computed(()=>props.entry?.last_trap_received);
const latestIsHint=computed(()=>Boolean(hint.value&&(!accepted.value||hint.value>=accepted.value)));
</script>
<template>
<div class="snmp-reception" :class="{'notice notice-warning':latestIsHint,'snmp-reception-compact':compact}" role="status">
  <template v-if="latestIsHint">
    <strong>{{t('SNMPv3-Trap empfangen · Kompatibilitätsmodus')}}</strong>
    <span class="snmp-reception-time">{{timestamp(hint)}}</span>
    <p>{{t('Signatur und Entschlüsselung geprüft · Aktualität unbestätigt. Geräteabfrage angefordert.')}}</p>
    <small v-if="accepted">{{t('Letzter regulär akzeptierter Trap:')}} {{timestamp(accepted)}}</small>
    <small v-else>{{t('Noch kein regulär akzeptierter Trap gespeichert.')}}</small>
  </template>
  <template v-else>
    <strong v-if="!compact">{{t('Letzter Trap-Eingang')}}</strong>
    <span class="snmp-reception-time">{{accepted?timestamp(accepted):t('Noch kein Trap-Eingang nachgewiesen.')}}</span>
    <small v-if="hint">{{t('Letzter Kompatibilitätseingang · nur Abfrage:')}} {{timestamp(hint)}}</small>
  </template>
</div>
</template>
