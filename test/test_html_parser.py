import unittest
from xml.etree.ElementTree import tostring

import tutil
from webvulnscan.html_parser import parse_html


class HTMLParserTests(unittest.TestCase):
    def test_valid(self):
        log = tutil.TestLog()
        html = '<html><head>&uuml; &auml;</head></html>'
        parser = parse_html(html, "http://example.site", log=log)
        self.assertEquals(len(log.entries), 0)

    def test_forgot_close(self):
        log = tutil.TestLog()
        html = '<html><body><theforgottentag>foo</body></html>'
        parse_html(html, "http://example.site", log=log)
        log.assertFound(u'Unclosed')
        log.assertFound(u'theforgottentag')
        self.assertEquals(len(log.entries), 1)

    def test_forgot_close_2(self):
        log = tutil.TestLog()
        html = '<html><body><theforgottentag><alsonot>foo</body></html>'
        parse_html(html, "http://example.site", log=log)
        log.assertFound(u'Unclosed')
        log.assertFound(u'theforgottentag')
        log.assertFound(u'alsonot')
        self.assertEquals(len(log.entries), 2)

    def test_superflupus_close(self):
        log = tutil.TestLog()
        html = '<html><body>foo</superfluous></body></html>'
        parse_html(html, "http://example html", log=log)
        log.assertFound(u'superfluous')
        self.assertEquals(len(log.entries), 1)

    def test_close_after_root(self):
        log = tutil.TestLog()
        html = '<html><body>foo</body></html></superfluous>'
        parse_html(html, "http://example.site", log=log)
        log.assertFound(u'superfluous')
        log.assertFound(u'after root')
        self.assertEquals(len(log.entries), 1)

    def test_parse_empty(self):
        log = tutil.TestLog()
        html = ''
        parse_html(html, "http://example.site", log=log)
        self.assertEquals(len(log.entries), 1)

    def test_parse_textroot(self):
        log = tutil.TestLog()
        html = 'a'
        parse_html(html, "http://example.site", log=log)
        self.assertTrue(len(log.entries) >= 1)

    def test_parse_text_before_root(self):
        log = tutil.TestLog()
        html = 'a<b></b>'
        parse_html(html, "http://example.site", log=log)
        log.assertFound(u'Text')
        self.assertEquals(len(log.entries), 1)

    def test_parse_text_after_root(self):
        log = tutil.TestLog()
        html = '<b/>c'
        parse_html(html, "http://example.site", log=log)
        log.assertFound(u'Text')
        self.assertEquals(len(log.entries), 1)

    def test_fixup_forgotten_closing(self):
        log = tutil.TestLog()
        html = '<html><body>go</body>'
        doc = parse_html(html, "http://example.site", log=log)
        self.assertEqual(tostring(doc), '<html><body>go</body></html>')
        log.assertFound(u'html')
        self.assertEquals(len(log.entries), 1)

if __name__ == '__main__':
    unittest.main()