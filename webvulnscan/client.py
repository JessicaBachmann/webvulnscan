from .compat import build_opener, Request, HTTPCookieProcessor, URLError, \
    urlencode, CookieJar, HTTPError

import gzip
import zlib
from .log import warn
from .page import Page


class StrangeContentType(Exception):
    """ Thrown when Client isn't able to find something. """
    def __init__(self):
        super(StrangeContentType, self).__init__()


class Client(object):
    """ Client provides a easy interface for accessing web content. """
    def __init__(self):
        """ Initalises the class. """
        self.cookie_jar = CookieJar()
        self.opener = self.setup_opener()
        self.visited_pages = set()
        self.additional_headers = {"Content-Encoding": "gzip, deflate"}

    def setup_opener(self):
        """ Builds the opener for the class. """
        cookie_handler = HTTPCookieProcessor(self.cookie_jar)
        opener = build_opener(cookie_handler)

        return opener

    def download(self, url, parameters=None, remember_visit=True):
        """
        Downloads a site, returns (status_code, response_data, headers)
        """
        if parameters is None:
            request = Request(url)
        else:
            data = urlencode(parameters).encode("utf-8")
            request = Request(url, data)

        for header, value in self.additional_headers.items():
            request.add_header(header, value)

        try:
            response = self.opener.open(request)
        except HTTPError as error:
            response = error
        except URLError as error:
            warn("Can't reach " + url)
            raise

        status_code = response.code
        headers = response.info()

        if headers.get('Content-Encoding') == "gzip":
            sim_file = gzip.GzipFile(fileobj=response)
            response_data = sim_file.read()
        elif headers.get('Content-Encoding') == "deflate":
            response_data = zlib.decompress(response.read())
        else:
            response_data = response.read()

        if remember_visit:
            self.visited_pages.update({url})

        return status_code, response_data, headers

    def download_page(self, url, parameters=None, remember_visit=True):
        """ Downloads the content of a site, returns it as page. """
        status_code, html, headers = self.download(url, parameters,
                                                   remember_visit)
        if "Content-Type" in headers:
            content_type, _, encoding = headers["Content-Type"].partition(";")

            if content_type == "text/html":
                attrib_name, _, charset = encoding.partition("=")
                if not attrib_name.strip() == "charset" or charset == "":
                    warn("Warning no Charset set under " + url)
                    html = html.decode("utf-8")
                else:
                    html = html.decode(charset)

            else:
                warn("Warning: strange content type: " + content_type)
                html = "<html></html>"

        else:
            warn("Warning no Content-Type header on " + url)
            html = html.decode("utf-8")

        return Page(url, html, headers, status_code)
