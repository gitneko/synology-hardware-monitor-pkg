import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from check_docs import check_links


class DocumentationLinks(unittest.TestCase):
    def test_archive_paths_fragments_and_images(self):
        files = {'README.md': b'[Guide](docs/Guide.md#scope--limits) ![preview](docs/image.jpg)',
                 'docs/Guide.md': b'# Guide\n## Scope & limits\n[Back](../README.md)',
                 'docs/image.jpg': b'example'}
        self.assertEqual(check_links(files), [])
        del files['docs/image.jpg']
        self.assertIn('missing local target', check_links(files)[0])

    def test_duplicate_headings_percent_encoding_and_broken_anchor(self):
        files = {'README.md': b'# Same\n# Same\n[Second](#same-1) [Guide](docs/A%20B.md#ok)',
                 'docs/A B.md': b'# OK'}
        self.assertEqual(check_links(files), [])
        files['docs/A B.md'] = b'# Other'
        self.assertIn('missing heading', check_links(files)[0])

    def test_code_external_urls_and_parent_escape(self):
        files = {'README.md': b'```md\n[ignored](missing.md)\n```\n`[ignored](other.md)`\n[External](https://example.invalid/)'}
        self.assertEqual(check_links(files), [])
        files['README.md'] += b'\n[Escape](../outside.md)'
        self.assertIn('missing local target', check_links(files)[0])
