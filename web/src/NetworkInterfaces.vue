<script setup>
import {computed,ref} from 'vue';
import {t} from './i18n.js';
import {networkReading,interfaceState} from './snmp.js';
import {observationStatus,observationLabel} from './health.js';
const props=defineProps({snapshot:Object,device:Object});
const ports=computed(()=>props.snapshot?.snmp?.network?.interfaces??[]);
const values=computed(()=>new Map((props.snapshot?.observations??[]).map(o=>[o.key,o])));
const link=port=>values.value.get(port.key)??{key:port.key,health:'unknown'};
const metric=(port,suffix)=>networkReading(values.value.get(`${port.key}:${suffix}`));
const details=port=>(props.snapshot?.observations??[]).filter(o=>o.key.startsWith(`${port.key}:`)&&!o.key.endsWith(':speed'));
const expanded=ref(new Set());
function toggle(port){if(expanded.value.has(port.key))expanded.value.delete(port.key);else expanded.value.add(port.key);}
const metricLabel=o=>t(({in_octets:'Eingehender Verkehr',out_octets:'Ausgehender Verkehr',in_errors:'Eingehende Fehler',out_errors:'Ausgehende Fehler',in_discards:'Eingehende Verwerfungen',out_discards:'Ausgehende Verwerfungen',duplex:'Duplex'})[o.key.split(':').at(-1)]??o.label);
</script>
<template>
  <section class="network-interfaces">
    <h3>{{t('Erkannte Netzwerkschnittstellen')}} ({{ports.filter(p=>p.present).length}})</h3>
    <p class="form-note detail-note">{{t('Linkalarme gelten für zuvor aktive Ports. Raten benötigen zwei gültige Messungen; Neustarts, Zählerrücksetzungen und unklare Überläufe werden nicht als Verkehrsspitzen interpretiert.')}}</p>
    <div class="interface-table-scroll">
      <table>
        <thead><tr><th>{{t('Schnittstelle')}}</th><th>{{t('Link')}}</th><th>{{t('Geschwindigkeit')}}</th><th>{{t('Verkehr ein / aus')}}</th><th>{{t('Zustand')}}</th></tr></thead>
        <tbody v-for="port in ports" :key="port.key">
          <tr>
            <td>
              {{port.name}}
              <small v-if="port.alias" class="assessment-reason">{{port.alias}}</small>
              <small class="assessment-reason">{{port.kind===24?t('Loopback · keine Linküberwachung'):port.seen_up?t('Zuvor aktiv · Linküberwachung aktiv'):t('Noch kein aktiver Link beobachtet')}}</small>
              <button v-if="details(port).length" type="button" class="interface-toggle" :aria-expanded="expanded.has(port.key)" :aria-controls="`${port.key}:readings`" @click="toggle(port)">
                <span aria-hidden="true">{{expanded.has(port.key)?'▾':'▸'}}</span> {{t('Weitere Messwerte')}}<span class="sr-only"> · {{port.name}}</span>
              </button>
            </td>
            <td>{{interfaceState(port)}}</td><td>{{metric(port,'speed')}}</td><td>{{metric(port,'in_octets')}} / {{metric(port,'out_octets')}}</td>
            <td><span :class="['badge',observationStatus(link(port),snapshot,device)]">{{observationLabel(link(port),snapshot,device)}}</span></td>
          </tr>
          <tr v-show="expanded.has(port.key)" :id="`${port.key}:readings`" class="interface-readings-row">
            <td colspan="5">
              <dl v-if="expanded.has(port.key)" class="interface-readings">
                <div v-for="o in details(port)" :key="o.key">
                  <dt>{{metricLabel(o)}}</dt>
                  <dd>{{networkReading(o)}} <span :class="['badge',observationStatus(o,snapshot,device)]">{{observationLabel(o,snapshot,device)}}</span></dd>
                </div>
              </dl>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
    <p v-if="snapshot.snmp.network.truncated" class="error interface-error">{{t('Die Schnittstellenerkennung hat ihre Begrenzung erreicht. Die Abdeckung ist unvollständig.')}}</p>
  </section>
</template>
