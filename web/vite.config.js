import { defineConfig } from 'vite';
import vue from '@vitejs/plugin-vue';
import {readFileSync} from 'node:fs';
const info=readFileSync(new URL('../packaging/INFO.dsm7',import.meta.url),'utf8');
const version=info.match(/^version="([^"]+)"/m)[1];
export default defineConfig({
  plugins:[vue(),{
    name:'hardware-monitor-build-identity',
    generateBundle(){this.emitFile({type:'asset',fileName:'ui-build.json',source:JSON.stringify({version})+'\n'});},
  }],
  define:{__UI_BUILD__:JSON.stringify(version)},
  base:'./',build:{target:'es2018'},
});
