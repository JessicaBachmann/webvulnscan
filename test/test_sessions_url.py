import unittest
import sys

import tutil
import webvulnscan.attacks.session_url

#Session ID 32 characters mostly with GET method POST also possible

def make_client(headers):
    headers['Content-Type'] = 'text/html; charset=utf-8'
    return tutil.TestClient({
        '/':(200, b'<html></html>, headers),
    })


class SessionUrl(unittest.TestCase):
    def test_static_site(self):
        client = make_client({})
        client.run_attack(webvulnscan.attacks.session_url)
        client.log.assert_count(0)

    #test site with session id in URI POST
    def test_site_with_id(self):
        client = make_client({
            "Set-Cookie" : "random = test"
            "Method" : "POST"
        })
        client.run_attack(webvulnscan.attacks.session_url)
        client.log.assert_count(1)
        
    #test site with session id in URI GET
    def test_site_with_id(self):
        client = make_client({
            "Set-Cookie" : "random = test"
            "Method" : "GET"
        })
        client.run_attack(webvulnscan.attacks.session_url)
        client.log.assert_count(1)

