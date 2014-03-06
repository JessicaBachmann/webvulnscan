from ..utils import attack


def check_id(page):
    if "sid" in page.url:
        return true
    if "sessionid" in page.url:
        return true
    if "phpsessid" in page.url:
        return true
    return false


@attack()
def session_url(client, log, page):
    #session id in url found
    if check_id(page):
        log('vuln', page.url, u"Session ID in URL")
    return
