import {t} from './i18n.js';
// Authentication is enforced by the CGI/service. Never retain a previous
// user's dashboard when a refresh cannot confirm the current DSM session.
import {dsmHeaders} from './dsm-session.js';

export async function updateSession(state, request = fetch, signal) {
  try {
    state.authRequired = false;
    const headers = await dsmHeaders(request, signal);
    const options = {credentials: 'same-origin', cache: 'no-store', redirect: 'error', headers, signal};
    const response = await request('./api.cgi', options);
    state.authRequired = response.status === 401 || response.status === 403;
    if (state.authRequired) {
      // DSM may replace the 403 JSON body with its HTML error page. Use the
      // reduced diagnostic endpoint with the same cookie/token for a fixed code.
      let code = 'api_access_denied';
      try {
        const diagnostic = await request('./api.cgi?diagnose=1', options);
        const body = await diagnostic.json();
        if (diagnostic.ok && body.source === 'hardware-monitor' &&
            typeof body.code === 'string' && /^(?:cgi|dsm|api|application)_[a-z0-9_]{1,64}$/.test(body.code)) code = body.code;
      } catch { /* No raw response or secret enters the visible error. */ }
      throw new Error(t("DSM-Anmeldung oder Anwendungsberechtigung fehlt. Diagnose: {0}",code));
    }
    const body = await response.json();
    if (!response.ok || body.ok !== true || !body.data?.user?.name) {
      throw new Error(body.error || t("Daten konnten nicht geladen werden."));
    }
    state.dashboard = body.data;
    state.error = '';
    state.authRequired = false;
  } catch (error) {
    state.dashboard = null;
    if (error.message === 'dsm_session_required') state.authRequired = true;
    if (error.message === 'dsm_session_required') state.error = t("Bitte zuerst in DSM anmelden.");
    else if (error.message === 'dsm_session_response_invalid') state.error = t("Die DSM-Sitzung konnte nicht geprüft werden.");
    else state.error = error.name === 'AbortError' ? t("Zeitüberschreitung beim Laden.") : error.message;
  }
}
