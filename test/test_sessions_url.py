from __future__ import unicode_literals
import unittest
import sys

import tutil
import webvulnscan.attacks.session_url

#session id's in URL can appear in various forms
#this test creates forms of sid, sessionid, phpsessid


def make_client(headers):
    headers['Content-Type'] = 'text/html; charset=utf-8'
    return tutil.TestClient({
        '/': (200, b'<html></html>', headers),
    })


class SessionUrl(unittest.TestCase):
    #creating site without any session
    def test_static_site(self):
        client = make_client({})
        client.run_attack(webvulnscan.attacks.session_url)
        client.log.assert_count(0)

    #sid in link
    def test_site_with_post(self):
        client = tutil.TestClient({
            '/': '<html>\
                <a href="www.sample.org/index.html?\
                sid=edb0e8665db4e9042fe0176a89aade16">link1</a>\
                </html>'
        })
        client.run_attack(webvulnscan.attacks.session_url)
        client.log.assert_count(1)

    #sessionid in link
    def test_site_with_get(self):
        client = tutil.TestClient({
            '/': '<html>\
                <a href="www.sample.org/index.html?\
                sessionid=edb0e8665db4e9042fe0176a89aade16">link2</a>\
                </html>'
        })
        client.run_attack(webvulnscan.attacks.session_url)
        client.log.assert_count(1)

    #phpsessid in link
    def test_site_with_get(self):
        client = tutil.TestClient({
            '/': '<html>\
               <a href="www.sample.org/index.html?\
               phpsessid=edb0e8665db4e9042fe0176a89aade16">link3</a>\
               </html>'
        })
        client.run_attack(webvulnscan.attacks.session_url)
        client.log.assert_count(1)
