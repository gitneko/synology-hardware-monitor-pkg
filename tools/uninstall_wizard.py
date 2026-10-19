"""Generate localized DSM uninstall wizards without a second frontend toolchain."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def write_wizards(destination):
    source = ROOT/'packaging/wizard'
    translations = json.loads((source/'strings.json').read_text())
    template = (source/'uninstall_uifile.sh').read_text()
    javascript = (source/'uninstall.js').read_text()
    destination.mkdir(parents=True, exist_ok=True)
    for language, text in translations.items():
        legacy = [{
            'step_title': text['title'],
            'items': [{
                'type': 'multiselect',
                'desc': text['description'],
                'subitems': [{
                    'key': 'wizard_delete_data',
                    'desc': text['checkbox'],
                    'defaultValue': False,
                }],
            }],
        }]
        modern = [{
            'custom_render_name': 'hardware_monitor_uninstall',
            'custom_render_fn': javascript.replace('__WIZARD_TEXT__', json.dumps(text, ensure_ascii=False)),
        }]
        script = template.replace('__MODERN_WIZARD__', json.dumps(modern, ensure_ascii=False))
        script = script.replace('__LEGACY_WIZARD__', json.dumps(legacy, ensure_ascii=False))
        output = destination/f'uninstall_uifile_{language}.sh'
        output.write_text(script)
        output.chmod(0o755)
        if language == 'enu':
            fallback = destination/'uninstall_uifile.sh'
            fallback.write_text(script)
            fallback.chmod(0o755)
