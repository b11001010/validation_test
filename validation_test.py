import re
from urllib.parse import urlparse

from cerberus import Validator


class RegexConfig:

    REGEX_FQDN = r"^(?=^.{1,255}$)(^(?:(?!\.|-)([\w\-\*]+)\.)+(?:[\w\-\*]+)$)$"
    REGEX_URL = r"^(?:\w+:\/\/)?[\w.-]+(?:\.[\w\.-]+)+[\w\-\._~:/?#[\]@!\$&'\(\)\*\+,;=.]+$"
    REGEX_EMAIL_ADDR = r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
    REGEX_IPV4 = r"^(?:(?:^|\.)(?:2(?:5[0-5]|[0-4]\d)|1?\d?\d)){4}$"
    # https://www.helpsystems.com/intermapper/ipv6-test-address-validation, used under CC BY-SA 3.0 / Modified from original
    REGEX_IPV6 = r"^((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?$"


class MyValidator(Validator):

    def _normalize_coerce_parse_fqdn(self, value):
        fqdn = urlparse(value).hostname
        if fqdn is None:
            fqdn = urlparse("//" + value).hostname
        return fqdn

    def _validator_fqdn(self, field, value):
        if value is None or not re.match(RegexConfig.REGEX_FQDN, value):
            msg = "Invalid fqdn: %s" % value
            self._error(field, msg)

    def _validator_url(self, field, value):
        if value is None or not re.match(RegexConfig.REGEX_URL, value):
            msg = "Invalid url: %s" % value
            self._error(field, msg)

    def _validator_ipv4(self, field, value):
        if value is None or not re.match(RegexConfig.REGEX_IPV4, value):
            msg = "Invalid ipv4: %s" % value
            self._error(field, msg)

    def _validator_ipv6(self, field, value):
        if value is None or not re.match(RegexConfig.REGEX_IPV6, value):
            msg = "Invalid ipv6: %s" % value
            self._error(field, msg)

    def _validator_email_addr(self, field, value):
        if value is None or not re.match(RegexConfig.REGEX_EMAIL_ADDR, value):
            msg = "Invalid email_addr: %s" % value
            self._error(field, msg)


if __name__ == "__main__":

    # test schema
    schema = {
        'fqdn': {
            'type': 'string',
            'validator': 'fqdn',
        },
        'ipv4': {
            'type': 'string',
            'validator': 'ipv4',
        },
        'ipv6': {
            'type': 'string',
            'validator': 'ipv6',
        },
        'email_addr': {
            'type': 'string',
            'validator': 'email_addr',
        },
        'url': {
            'type': 'string',
            'validator': 'url',
        },
        'fqdn_in_url': {
            'type': 'string',
            'validator': 'fqdn',
            'coerce': 'parse_fqdn'
        },
    }
    # test data
    data = {
        'fqdn': 'xn--r8jz45g.xn--zckzah',
        'ipv6': 'fe80:0000:0000:0000:0204:61ff:fe9d:f156',
        'email_addr': 'www.@xn--r8jz45g.xn--zckzah',
        'url': 'www.exaple.com:80/products?id=1&page=2#test',
        'fqdn_in_url': 'www.exaple.com:80/products?id=1&page=2',
    }
    # validate
    v = MyValidator(schema)
    print(v.validate(data))  # True
    print(v.errors)  # {}
    print(v.document['fqdn_in_url'])  # www.exaple.com
