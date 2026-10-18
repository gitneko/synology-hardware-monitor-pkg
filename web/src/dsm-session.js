import {currentLanguage} from './i18n.js';
// Read the existing DSM browser session. Never submit credentials, log the
// response, persist the token or place it in a URL.
export async function dsmHeaders(request, signal) {
  const response = await request('/webman/login.cgi', {
    credentials: 'same-origin', cache: 'no-store', redirect: 'error', signal,
  });
  let session;
  try { session = await response.json(); } catch { throw new Error('dsm_session_response_invalid'); }
  if (!session || typeof session !== 'object' || Array.isArray(session)) throw new Error('dsm_session_response_invalid');
  if (!response.ok || session.success !== true) throw new Error('dsm_session_required');
  // DSM configurations with CSRF protection disabled can omit SynoToken.
  // The native helper must still verify their cookie and application role.
  const token = session.SynoToken;
  if (token === undefined || token === '') return {'X-HardwareMonitor-Language':currentLanguage()};
  if (typeof token !== 'string' || token.length > 4096 || /[\x00-\x20\x7f]/.test(token)) {
    throw new Error('dsm_session_response_invalid');
  }
  return {'X-SYNO-TOKEN': token,'X-HardwareMonitor-Language':currentLanguage()};
}
