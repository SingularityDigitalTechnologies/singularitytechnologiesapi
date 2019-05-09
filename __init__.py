import base64
import datetime
import hmac
import json
import os
import requests

from collections import namedtuple
from hashlib import sha512
from urllib.parse import urlparse
from urllib.parse import urlunparse

from requests import Request
from requests import Session

from singularityapi.exceptions import APIUsageException


Endpoint = namedtuple('Endpoint', ['path', 'method'])

PING = Endpoint(path='/ping', method='GET')

ATLAS_STATUS = Endpoint(path='/status', method='GET')
BATCH_INFO = Endpoint(path='/batch', method='GET')
BATCH_CREATE = Endpoint(path='/batch', method='POST')
JOB_INFO = Endpoint(path='/job', method='GET')

GENERATE_HMAC = Endpoint(path='/sec/key', method='POST')
USER_ADD = Endpoint(path='/user', method='POST')
COMPANY_ADD = Endpoint(path='/company', method='POST')
DATASET = Endpoint(path='/data', method='POST')
DATASET_SUMMARY = Endpoint(path='/data/%s', method='GET')
SHARD = Endpoint(path='/data/%s/shard/%s', method='POST')
JOB_CANCEL = Endpoint(path='/job/%s', method='DELETE')
BATCH_CANCEL = Endpoint(path='/batch/%s', method='DELETE')


class AbstractRequest(object):
    def __init__(self, options, *args, **kwargs):
        api_url = options.get('api_url')
        url_params = urlparse(api_url)
        if not url_params[0]:
            raise APIUsageException('api_url requires a scheme e.g. http')

        self.scheme = url_params[0]
        self.netloc = url_params[1]

        self.secret = options.get('secret', '')
        self.api_key = options.get('api_key', '')

    def generate_sha512_hmac(self, secret, method, endpoint, payload):
        base_sig = '%s\n%s\n%s' % (method, endpoint, payload)
        return hmac.new(
            secret.encode('utf-8'),
            bytes(base_sig.encode('utf-8')),
            digestmod=sha512
        ).hexdigest()

    def get_headers(self, endpoint, payload):
        if not self.secret:
            print('WARNING: API key and/or secret not set')
            return {}

        signature = self.generate_sha512_hmac(
            self.secret,
            endpoint.method,
            endpoint.path,
            payload
        )

        return {
            'X-singularity-apikey': self.api_key,
            'X-singularity-signature': signature,
        }

    def send_request(self, endpoint, payload='', headers=None):
        url = urlunparse((
            self.scheme,
            self.netloc,
            endpoint.path,
            '',
            '',
            ''
        ))

        headers = headers or {}
        request = Request(endpoint.method, url, data=payload, headers=headers)

        try:
            response = Session().send(request.prepare())
        except requests.exceptions.ConnectionError:
            raise APIUsageException('Unable to establish connection with API')
        else:
            return response

    def request(self, endpoint, payload=''):
        headers = self.get_headers(endpoint, payload)
        response = self.send_request(
            endpoint,
            payload=payload,
            headers=headers,
        )

        trace = response.headers.get('X-atlas-trace', '')

        payload = None
        try:
            payload = response.json()
        except ValueError:
            pass

        return payload, response.status_code


class Ping(AbstractRequest):

    def run(self):
        return self.request(PING)


class BatchCreate(AbstractRequest):

    def __init__(self, options, *args, **kwargs):
        super().__init__(options, *args, **kwargs)

        self.payload = options.get('payload', '')

        self.mode = options.get('mode', '')
        if not self.mode:
            raise APIUsageException('Mode must be set to either Pilot or Production')

        cpus = options.get('cpus') or 0
        if type(cpus) != int:
            if not cpus.isdigit():
                raise APIUsageException('CPUs must be an integer number')

        self.cpus = int(cpus)
        gpus = options.get('gpus') or 0
        if type(gpus) != int:
            if not gpus.isdigit():
                raise APIUsageException('GPUs must be an integer number')

        self.gpus = int(gpus)

    def run(self):
        payload = json.dumps({
            'mode': self.mode,
            'jobs': self.payload,
            'requisitions': {
                'cpu': {'kind': 'cpu', 'quantity': self.cpus},
                'gpu': {'kind': 'gpu', 'quantity': self.gpus},
            }
        })

        return self.request(BATCH_CREATE, payload)


class BatchStatus(AbstractRequest):

    def __init__(self, options, *args, **kwargs):
        super().__init__(options, *args, **kwargs)

        self.endpoint = BATCH_INFO

        uuid = options.get('uuid')
        if uuid:
            self.endpoint = Endpoint(path='/batch/%s' % uuid, method='GET')

    def run(self):
        return self.request(self.endpoint)


class BatchSummary(AbstractRequest):

    def __init__(self, options, *args, **kwargs):
        super().__init__(options, *args, **kwargs)

        self.endpoint = BATCH_INFO

        self.since = None
        since = options.get('since')
        if since:
            self.since = datetime.datetime.strptime(since, '%Y-%m-%d')

    def run(self):
        return self.request(self.endpoint)


class JobStatus(AbstractRequest):

    def __init__(self, options, *args, **kwargs):
        super().__init__(options, *args, **kwargs)

        self.endpoint = JOB_INFO

        uuid = options.get('uuid')
        if uuid:
            self.endpoint = Endpoint(path='/job/%s' % uuid, method='GET')

    def run(self):
        return self.request(self.endpoint)


class AtlasStatus(AbstractRequest):

    def __init__(self, options, *args, **kwargs):
        super().__init__(options, *args, **kwargs)

        self.endpoint = ATLAS_STATUs

    def run(self):
        return self.request(self.endpoint)


class GenerateHMAC(AbstractRequest):

    def __init__(self, options, *args, **kwargs):
        super().__init__(options, *args, **kwargs)

        self.email = options.get('email')
        self.endpoint = GENERATE_HMAC

    def run(self):
        return self.request(self.endpoint, json.dumps({'email': self.email}))


class Cancel(AbstractRequest):
    def __init__(self, options, kind, **kwargs):
        super().__init__(options, kind, **kwargs)

        self.kind = kind
        self.uuid = options.get('uuid')

    def run(self):
        if self.kind == 'batch':
            path = BATCH_CANCEL.path % self.uuid
        elif self.kind == 'job':
            path = JOB_CANCEL.path % self.uuid

        endpoint = Endpoint(path=path, method='DELETE')
        return self.request(endpoint)


class UserAdd(AbstractRequest):
    def __init__(self, options, *args, **kwargs):
        super().__init__(options, *args, **kwargs)

        self.first_name = options.get('first_name', '')
        self.last_name = options.get('last_name', '')
        self.email = options.get('email', '')
        self.user_type = options.get('user_type', '').lower()
        self.password = options.get('password', '')

        self.endpoint = UsER_ADD

    def run(self):
        return self.request(
            self.endpoint,
            json.dumps({
                'first_name': self.first_name,
                'last_name': self.last_name,
                'email': self.email,
                'user_type': self.user_type,
                'password': self.password,
            })
        )


class CompanyAdd(AbstractRequest):
    def __init__(self, options, *args, **kwargs):
        super().__init__(options, *args, **kwargs)

        self.name = options.get('name')
        self.endpoint = COMPANY_ADD

    def run(self):
        return self.request(self.endpoint, json.dumps({'name': self.name}))


class DataSetAdd(AbstractRequest):
    def __init__(self, options, *args, **kwargs):
        super().__init__(options, *args, **kwargs)

        self.name = options.get('name')
        location = options.get('location')
        if not location:
            raise APIUsageException('Location not defined')

        imprint_location = options.get('imprint_location')
        if not imprint_location:
            raise APIUsageException('Imprint location not defined')

        pilot_count = options.get('pilot_count', 0)
        if not pilot_count:
            raise APIUsageException('Pilot Count not defined')

        if not pilot_count.isdigit():
            raise APIUsageException('Pilot Count must be an integer')

        self.pilot_count = int(pilot_count)

        self.dataset_endpoint = DATASET

        self.sharder = Sharder(location, imprint_location)

    def run(self):
        request_payload = json.dumps({
            'name': self.name,
            'pilot_count': self.pilot_count
        })

        payload, _ = self.request(self.dataset_endpoint, request_payload)
        dataset_uuid = payload.get('dataset_uuid')
        if not dataset_uuid:
            raise APIUsageException('No dataset id recieved')

        for shard_id, shard in self.sharder.get_new_shards():
            shard_path = SHARD.path % (dataset_uuid, shard_id)
            endpoint = Endpoint(path=shard_path, method='POST')

            self.request(endpoint, base64.b64encode(shard).decode())


class DataSetSummary(AbstractRequest):
    def __init__(self, options, *args, **kwargs):
        super().__init__(options, *args, **kwargs)

        self.name = options.get('name')

    def run(self):
        path = DATASET_SUMMARY.path % self.name
        endpoint = Endpoint(path=path, method='GET')
        return self.request(endpoint)
