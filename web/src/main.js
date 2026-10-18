import { createApp } from 'vue';
import App from './App.vue';
import {initLanguage} from './i18n.js';
initLanguage();
import './style.css';
createApp(App).mount('#app');
