import unittest
import sys

import tutil
import webvulnscan.attacks.session_url

#creating site without any session
def make_client(headers):
    headers['Content-Type'] = 'text/html; charset=utf-8'
    return tutil.TestClient({
        '/':(200, b'<html></html>', headers),
    })
    

class SessionUrl(unittest.TestCase):
    headers = "Set-Cookie" : "random=test"
    def test_static_site(self):
        client = make_client({})
        client.run_attack(webvulnscan.attacks.session_url)
        client.log.assert_count(0)

    #test site/form with session id in URI POST
    def test_site_with_post(self):
        client = tutil.TestClient({
            '/': u'''<html>
                <form method = POST>
                    <input type="submit" />
                </form>
                </html>''', headers
        })
        client.run_attack(webvulnscan.attacks.session_url)
        client.log.assert_count(1)
        
    #test site/form with session id in URI GET
    def test_site_with_get(self):
        client = make_client({
            '/': u'''<html>
                <form method = GET>
                    <input type="submit" />
                </form>
                </html>''', headers
        })
        client.run_attack(webvulnscan.attacks.session_url)
        client.log.assert_count(1)

