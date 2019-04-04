# -*- coding: utf-8 -*-+
import json
import re
import urllib
from collections import OrderedDict
from time import sleep

from bs4 import BeautifulSoup

sslbl_cert_uri = 'https://sslbl.abuse.ch/ssl-certificates/'
sslbl_base_uri = 'https://sslbl.abuse.ch/'


class CertInfoJsonEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, CertInfo):
            dict = OrderedDict()
            dict['sha1'] = o.sha1_fp
            dict['CertCN'] = o.CertCN
            dict['IssuerDN'] = o.IssuerDN
            dict['Tls version'] = o.tls_ver
            dict['First Seen'] = o.FirstSeen
            dict['Listing Reason'] = o.reason
            dict['Listing Date'] = o.date
            return dict
        return super(CertInfoJsonEncoder, self).default(o)


class CertInfo():
    def __init__(self):
        self.sha1_fp = ''
        self.CertCN = ''
        self.IssuerDN = ''
        self.tls_ver = ''
        self.FirstSeen = ''
        self.reason = ''
        self.date = ''

        self.tbl_dict = {'SHA1 Fingerprint:': self._set_sha1_fp,
                         'Certificate Common Name (CN):': self._set_CertCN,
                         'Issuer Distinguished Name (DN):': self._set_IssuerDN,
                         'TLS Version:': self._set_tls_ver,
                         'First seen:': self._set_FirstSeen,
                         'Listing reason:': self._set_reason,
                         'Listing date:': self._set_date
                         }


    def _set_sha1_fp(self, value):
        self.sha1_fp = value
    def _set_CertCN(self, value):
        self.CertCN = value
    def _set_IssuerDN(self, value):
        self.IssuerDN = value
    def _set_tls_ver(self, value):
        self.tls_ver = value
    def _set_FirstSeen(self, value):
        self.FirstSeen = value
    def _set_reason(self, value):
        self.reason = value
    def _set_date(self, value):
        self.date = value

    def set_string(self, key, value):
        if key in self.tbl_dict:
            func = self.tbl_dict[key]
            func(value)


def get_html_body(uri):
    req = urllib.request.Request(uri)
    try:
        res = urllib.request.urlopen(req)
        return res.read().decode('utf-8')
    except:
        print('Error: can not open ' + uri)
        raise


def get_cert_links(html):
    soup = BeautifulSoup(html)
    al = soup.find_all('a', target='_parent', href=re.compile('/ssl-certificates/sha1/.*'))
    return [x.attrs['href'] for x in al]


def get_cert_info(html):
    cert = CertInfo()
    soup = BeautifulSoup(html)
    cont = soup.find('table', class_='table table-sm table-bordered')
    if cont is None:
        return None
    tbl_cont = [x for x in cont.contents if not x == '\n']
    for tc in tbl_cont:
        key = tc.contents[0].string
        value = tc.contents[1].string
        cert.set_string(key, value)
    return cert


def parse_each_certinfo(cert_links):
    parsed_list = []
    links = len(cert_links)
    cnt = 0
    error_pages = []
    for cl in cert_links:
        body = get_html_body(sslbl_base_uri + cl)
        cert = get_cert_info(body)
        if cert is None:
            error_pages.append(sslbl_base_uri + cl)
            continue
        parsed_list.append(cert)
        cnt += 1
        if cnt % 3 == 0:
            sleep(1)
        print('\rprocessing... %d/%d (%d%%)' % (cnt, links, (cnt*100) // links), end='')

    if error_pages:
        print('[+]error pages.')
        for x in error_pages:
            print(x)
    return parsed_list


def output_result(result):
    txt = json.dumps(result, cls=CertInfoJsonEncoder,
                     indent=4, separators=(',', ': '))
    with open('sslbl_cert_info.json', 'w') as f:
        f.write(txt)


def main():
    body = get_html_body(sslbl_cert_uri)
    links = get_cert_links(body)
    result = parse_each_certinfo(links)
    output_result(result)
    return


if __name__ is '__main__':
    main()
