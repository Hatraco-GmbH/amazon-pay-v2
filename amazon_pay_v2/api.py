import base64
import collections
import datetime
import hashlib
import json
import uuid
from collections import OrderedDict
from urllib import parse

import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from urllib.parse import quote


def create_idempotency_key():
    return str(uuid.uuid4()).replace('-', '')


class AmazonPayAPIV2:
    HASH_ALGORITHM = 'sha256'
    AMAZON_SIGNATURE_ALGORITHM = 'AMZN-PAY-RSASSA-PSS'
    API_VERSION = 'v2'
    USER_AGENT = 'AmazonPayAPIV2/HatracoGmbH/Python3'

    host = None
    environment = None
    version = None

    region = None

    service_hosts = {
        'eu': 'pay-api.amazon.eu',
        'na': 'pay-api.amazon.com',
        'jp': 'pay-api.amazon.jp'
    }

    region_map = {
        'eu': 'eu',
        'de': 'eu',
        'uk': 'eu',
        'us': 'na',
        'na': 'na',
        'jp': 'jp'
    }

    def __init__(self, private_key_path, public_key, region=None, environment=None):
        """
        Args:
            private_key_path: Path to your private key file
            region: Possible values: 'eu', 'de', 'uk', 'us', 'na', 'jp'
            environment: "live" or "sandbox"
        """
        self.public_key = public_key

        self.environment = environment if environment else 'live'

        self.region = region

        if not region or region not in list(self.region_map.keys()):
            raise Exception(f"The 'region' argument is a required parameter and must have on of the following values: {','.join(list(self.region_map.keys()))}")

        self.host = self.service_hosts[self.region_map[region]]

        with open(private_key_path, 'rb') as f:
            self.private_key = load_pem_private_key(f.read(), password=None)

    def _check_for_critical_data_api(self, url, method, payload):
        payment_critical_data_apis = [f'/live/account-management/{self.API_VERSION}/accounts', f'/sandbox/account-management/{self.API_VERSION}/accounts']
        allowed_methods = ['POST', 'PUT', 'PATCH']

        for api in payment_critical_data_apis:
            if api in url and method in allowed_methods:
                return ''

        return payload

    def _get_post_signed_headers(self, method, url, request_parameters, payload, headers):
        payload = self._check_for_critical_data_api(url, method, payload)

        pre_signed_headers = {
            'accept': 'application/json',
            'content-type': 'application/json',
            'x-amz-pay-region': self.region,
        }

        if headers:
            for key, value in headers.items():
                if key.lower() == 'x-amz-pay-idempotency-key':
                    if value:
                        pre_signed_headers['x-amz-pay-idempotency-key'] = value

        ts = datetime.datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')

        signature = self._create_signature(method, url, request_parameters, pre_signed_headers, payload, ts)

        canonical_headers = self._get_canonical_headers(pre_signed_headers)
        canonical_headers['X-Amz-Pay-Date'] = ts
        canonical_headers['X-Amz-Pay-Host'] = self.host

        signed_headers = f'SignedHeaders={self._get_canonical_header_names(canonical_headers)}, Signature={signature}'

        final_headers = {
            'accept': pre_signed_headers['accept'],
            'content-type': pre_signed_headers['content-type'],
            'x-amz-pay-host': self.host,
            'x-amz-pay-date': ts,
            'x-amz-pay-region': self.region,
            'authorization': f'{self.AMAZON_SIGNATURE_ALGORITHM} PublicKeyId={self.public_key}, {signed_headers}',
            'user-agent': self.USER_AGENT
        }
        final_headers_sorted = collections.OrderedDict()
        for key in sorted(final_headers.keys()):
            final_headers_sorted[key] = final_headers[key]
        return final_headers_sorted

    def _call(self, method, endpoint, payload=None, headers=None, query_parameters=None):
        if not endpoint.startswith('/'):
            endpoint = f'/{endpoint}'

        if payload:
            json_payload = json.dumps(payload, separators=(',', ':'))
        else:
            json_payload = ''

        url = f'https://{self.host}/{self.environment}/{self.API_VERSION}{endpoint}'

        if query_parameters:
            if type(query_parameters) != dict:
                raise Exception("query_parameters must be a dictionary; e.g. {'accountId': 'ABCD1234XYZIJK'}")
            request_parameters = query_parameters
            url = f'{url}?{self._get_canonical_query_string(query_parameters)}'
        else:
            request_parameters = {}

        post_signed_headers = self._get_post_signed_headers(method, url, request_parameters, json_payload, headers)

        if headers:
            if type(headers) != dict:
                raise Exception("headers must be a dictionary; e.g. {'x-amz-pay-authtoken': 'abcd1234xyzIJK'}")
            for key, value in headers.items():
                post_signed_headers[key] = value

        if not json_payload:
            json_payload = None

        response = requests.request(method.lower(), url, data=json_payload, headers=post_signed_headers)
        return response

    @staticmethod
    def _get_canonical_url(url):
        canonical_url_parts = parse.urlparse(url)
        return canonical_url_parts.path

    def _create_signature(self, method, url, request_parameters, pre_signed_headers, json_payload, time_stamp):
        pre_signed_headers['x-amz-pay-date'] = time_stamp
        pre_signed_headers['x-amz-pay-host'] = self.host

        hashed_payload = self._hex_and_hash(json_payload).lower()
        canonical_url = self._get_canonical_url(url)
        canonical_query_string = self._get_canonical_query_string(request_parameters)
        canonical_headers = self._get_canonical_header_string(pre_signed_headers)
        signed_headers = ';'.join(sorted([k.lower() for k in pre_signed_headers.keys()]))

        canonical_request = '\n'.join([method, canonical_url, canonical_query_string, canonical_headers, '', signed_headers, hashed_payload])
        hashed_canonical_request = self._hex_and_hash(canonical_request).lower()
        str_to_sign = f'{self.AMAZON_SIGNATURE_ALGORITHM}\n{hashed_canonical_request}'.encode('utf-8')

        signed_canonical_request = self._rsa_sign(str_to_sign)

        if not signed_canonical_request:
            raise Exception("Unable to sign your request in _create_signature. Is the private key correct?")

        signature = base64.b64encode(signed_canonical_request).decode('utf-8')
        return signature

    def _rsa_sign(self, message):
        signature = self.private_key.sign(
            data=message,
            padding=padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=20),
            algorithm=hashes.SHA256()
        )
        return signature

    def generate_button_signature(self, json_payload):
        hashed_payload = self._hex_and_hash(json_payload)

        hashed_and_salted_payload = f"{self.AMAZON_SIGNATURE_ALGORITHM}\n{hashed_payload}"
        hashed_and_salted_payload = hashed_and_salted_payload.encode('utf-8')

        signature = self._rsa_sign(hashed_and_salted_payload)

        if not signature:
            raise Exception("Unable to sign your payload in generate_button_signature. Is the private key correct?")

        base64_encoded_signature = base64.b64encode(signature)
        return base64_encoded_signature.decode('utf-8')

    @staticmethod
    def _hex_and_hash(data):
        try:
            data = data.encode('utf-8')
        except AttributeError as e:
            print(e)

        m = hashlib.sha256()
        m.update(data)

        return m.hexdigest()

    @staticmethod
    def _get_canonical_headers(headers):
        headers = {k.lower().strip(): v.strip() for k, v in headers.items()}
        sorted_keys = sorted(list(headers.keys()))
        sorted_headers = OrderedDict()
        for key in sorted_keys:
            sorted_headers[key] = headers[key]
        return sorted_headers

    @staticmethod
    def _get_canonical_header_names(headers):
        header_keys = sorted([k.lower() for k in (headers.keys())])
        return ';'.join(header_keys)

    def _get_canonical_header_string(self, headers):
        sorted_headers = self._get_canonical_headers(headers)
        header_data_list = []
        for k, v in sorted_headers.items():
            if isinstance(v, (list, tuple)):
                v = ' '.join(v)
            header_data_list.append(f'{k}:{v}')

        return '\n'.join(header_data_list)

    @staticmethod
    def _get_canonical_query_string(query_params):
        canonical_query_params = {}
        for key, value in query_params.items():
            if type(value) == list:
                index = 0
                for e in value:
                    index += 1
                    new_key = quote(f'{key}.{index}')
                    canonical_query_params[new_key] = quote(e)
            else:
                canonical_query_params[quote(key)] = quote(value)

        canonical_query_params = collections.OrderedDict(sorted(canonical_query_params.items()))
        canonical_query_string = '&'.join([f'{k}={v}' for k, v in canonical_query_params.items()])
        return canonical_query_string

    def get_checkout_session(self, session_id):
        endpoint = f'/checkoutSessions/{session_id}'
        method = 'GET'
        return self._call(method, endpoint)

    def create_checkout_session(self, payload, idempotency_key=None):
        endpoint = '/checkoutSessions/'
        method = 'POST'
        if idempotency_key:
            headers = {'x-amz-pay-idempotency-key': idempotency_key}
        else:
            headers = None
        return self._call(method, endpoint, payload, headers=headers)

    def update_checkout_session(self, session_id, payload):
        endpoint = f'/checkoutSessions/{session_id}'
        method = 'PATCH'
        return self._call(method, endpoint, payload)

    def complete_checkout_session(self, session_id, payload, idempotency_key=None):
        endpoint = f'/checkoutSessions/{session_id}/complete/'
        method = 'POST'
        if idempotency_key:
            headers = {'x-amz-pay-idempotency-key': idempotency_key}
        else:
            headers = None
        return self._call(method, endpoint, payload, headers=headers)

    def get_refund(self, refund_id):
        endpoint = f'/refunds/{refund_id}'
        method = "GET"
        return self._call(method, endpoint)

    def create_refund(self, payload, idempotency_key=None):
        endpoint = f'/refunds/'
        method = "POST"
        if idempotency_key:
            headers = {'x-amz-pay-idempotency-key': idempotency_key}
        else:
            headers = None
        return self._call(method, endpoint, payload, headers=headers)
