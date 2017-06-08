import collections
import datetime
import hashlib
import hmac
import json
import logging
import unittest
import uuid

import pytz
import requests


# TODO: Update the following variables to match your system
SECRET_KEY = 'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789'
BASE_URL = 'https://example.com'
PATH = '/path/to/your/endpoint'
PROPERTY_ID = 'abc123'

CLIENT_NAME = 'tripadvisor-vr'
TIMESTAMP_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
SIGNATURE_FORMAT = "VRS-HMAC-SHA512 timestamp={timestamp}, client={client}, signature={signature}"
QUERY_STRING_FORMAT = 'guests={guests}&propertyId={property_id}&arrival={arrival}&departure={departure}&requestId={request_id}'

logging.basicConfig(
    format='%(asctime)s %(levelname)s %(funcName)s %(message)s',
    level=logging.INFO
)

QueryParameters = collections.namedtuple(
    'QueryParameters',
    [
        'guests',
        'property_id',
        'arrival',
        'departure',
    ]
)

# TODO: Update the following test inputs to match your system
# Comment out a top-level key, value pair to skip that particular test
TEST_CASES = {
    'successful_response': QueryParameters(
        guests=7,
        property_id=PROPERTY_ID,
        arrival='2018-07-01',
        departure='2018-08-01',
    ),
    'min_stay_violation': QueryParameters(
        guests=16,
        property_id=PROPERTY_ID,
        arrival='2018-08-01',
        departure='2018-08-05',
    ),
    'date_range_unavailable_violation': QueryParameters(
        guests=17,
        property_id=PROPERTY_ID,
        arrival='2018-08-01',
        departure='2018-08-02',
    ),
    'turnday_violation': QueryParameters(
        guests=18,
        property_id=PROPERTY_ID,
        arrival='2018-08-02',
        departure='2018-08-03',
    ),
    'property_inactive_error': QueryParameters(
        guests=10,
        property_id=PROPERTY_ID,
        arrival='2018-08-03',
        departure='2018-08-04',
    ),
    'date_range_invalid_error': QueryParameters(
        guests=11,
        property_id=PROPERTY_ID,
        arrival='2018-08-03',
        departure='2018-08-04',
    ),
    'party_size_invalid_error': QueryParameters(
        guests=12,
        property_id=PROPERTY_ID,
        arrival='2018-08-03',
        departure='2018-08-04',
    ),
    'other_error': QueryParameters(
        guests=13,
        property_id=PROPERTY_ID,
        arrival='2018-08-03',
        departure='2018-08-04',
    ),
}


class AssistedRateSpecTest(unittest.TestCase):
    s = requests.Session()

    @unittest.skipIf('successful_response' not in TEST_CASES, 'Test case not implemented')
    def test_successful_response(self):
        r = self.s.send(
            _get_request(TEST_CASES['successful_response']),
        )
        
        self.assertEqual(r.status_code, 200)
        
        r = r.json()

        self.assertIn('details', r)
        self.assertIn('baseRate', r['details'])
        self.assertIn('tax', r['details'])

    @unittest.skipIf('min_stay_violation' not in TEST_CASES, 'Test case not implemented')
    def test_min_stay_violation(self):
        r = self.s.send(
            _get_request(TEST_CASES['min_stay_violation']),
        )

        self.assertEqual(r.status_code, 200)

        r = r.json()

        self.assertIn('details', r)
        self.assertIn('baseRate', r['details'])
        self.assertIn('tax', r['details'])
        self.assertIn('eligibility', r)
        self.assertIn('tripViolations', r['eligibility'])

        min_stay_violations = [
            v for v in r['eligibility']['tripViolations']
            if v['violationCode'] == 'MIN_STAY_VIOLATION'
        ]

        self.assertEqual(len(min_stay_violations), 1)

        self.assertIn('minStay', min_stay_violations[0])
        self.assertIsInstance(min_stay_violations[0]['minStay'], int)
        self.assertGreater(min_stay_violations[0]['minStay'], 0)

    @unittest.skipIf('date_range_unavailable_violation' not in TEST_CASES, 'Test case not implemented')
    def test_date_range_unavailable(self):
        r = self.s.send(
            _get_request(TEST_CASES['date_range_unavailable_violation']),
        )

        self.assertEqual(r.status_code, 200)

        r = r.json()

        self.assertIn('details', r)
        self.assertIn('baseRate', r['details'])
        self.assertIn('tax', r['details'])
        self.assertIn('eligibility', r)
        self.assertIn('tripViolations', r['eligibility'])

        date_range_unavailable_violations = [
            v for v in r['eligibility']['tripViolations']
            if v['violationCode'] == 'DATE_RANGE_UNAVAILABLE'
        ]

        self.assertEqual(len(date_range_unavailable_violations), 1)

    @unittest.skipIf('turnday_violation' not in TEST_CASES, 'Test case not implemented')
    def test_turnday(self):
        r = self.s.send(
            _get_request(TEST_CASES['turnday_violation']),
        )

        self.assertEqual(r.status_code, 200)

        r = r.json()

        self.assertIn('details', r)
        self.assertIn('baseRate', r['details'])
        self.assertIn('tax', r['details'])
        self.assertIn('eligibility', r)
        self.assertIn('tripViolations', r['eligibility'])

        turnover_violations = [
            v for v in r['eligibility']['tripViolations']
            if v['violationCode'] == 'TURNOVER_VIOLATION'
        ]

        self.assertEqual(len(turnover_violations), 1)

        self.assertIn('turnover', turnover_violations[0])
        self.assertIn(turnover_violations[0]['turnover'], {'SUNDAY', 'MONDAY', 'TUESDAY', 'WEDNESDAY', 'THURSDAY', 'FRIDAY', 'SATURDAY'})

    @unittest.skipIf('property_inactive_error' not in TEST_CASES, 'Test case not implemented')
    def test_property_inactive_error(self):
        r = self.s.send(
            _get_request(TEST_CASES['property_inactive_error']),
        )

        self.assertEqual(r.status_code, 400)

        r = r.json()

        self.assertIn('errors', r)

        property_inactive_errors = [
            v for v in r['errors']
            if v['reason'] == 'PROPERTY_INACTIVE'
        ]

        self.assertEqual(len(property_inactive_errors), 1)

    @unittest.skipIf('date_range_invalid_error' not in TEST_CASES, 'Test case not implemented')
    def test_date_range_invalid_error(self):
        r = self.s.send(
            _get_request(TEST_CASES['date_range_invalid_error']),
        )

        self.assertEqual(r.status_code, 400)

        r = r.json()

        self.assertIn('errors', r)

        property_inactive_errors = [
            v for v in r['errors']
            if v['reason'] == 'DATE_RANGE_INVALID'
        ]

        self.assertEqual(len(property_inactive_errors), 1)

    @unittest.skipIf('party_size_invalid_error' not in TEST_CASES, 'Test case not implemented')
    def test_party_size_invalid_error(self):
        r = self.s.send(
            _get_request(TEST_CASES['party_size_invalid_error']),
        )

        self.assertEqual(r.status_code, 400)

        r = r.json()

        self.assertIn('errors', r)

        property_inactive_errors = [
            v for v in r['errors']
            if v['reason'] == 'PARTY_SIZE_INVALID'
        ]

        self.assertEqual(len(property_inactive_errors), 1)

    @unittest.skipIf('other_error' not in TEST_CASES, 'Test case not implemented')
    def test_other_error(self):
        r = self.s.send(
            _get_request(TEST_CASES['other_error']),
        )

        self.assertEqual(r.status_code, 400)

        r = r.json()

        self.assertIn('errors', r)

        property_inactive_errors = [
            v for v in r['errors']
            if v['reason'] == 'OTHER'
        ]

        self.assertGreaterEqual(len(property_inactive_errors), 1)


def _get_request(query_parameters):
    now = datetime.datetime.now(tz=pytz.UTC)
    body = ''

    query_string = QUERY_STRING_FORMAT.format(
        guests=query_parameters.guests,
        property_id=query_parameters.property_id,
        arrival=query_parameters.arrival,
        departure=query_parameters.departure,
        request_id=uuid.uuid4()
    )

    r = requests.Request(
        'GET',
        "{}{}?{}".format(BASE_URL, PATH, query_string),
    )

    signature = SIGNATURE_FORMAT.format(
        timestamp=now.strftime(TIMESTAMP_FORMAT),
        client=CLIENT_NAME,
        signature=_get_signature(
            r.method,
            PATH,
            query_string,
            now,
            body,
        )
    )

    logging.info(
        json.dumps(
            {
                'method': r.method,
                'path': PATH,
                'query_string': query_string,
                'body': body,
                'timestamp': now.strftime(TIMESTAMP_FORMAT),
                'client': CLIENT_NAME,
                'secret': SECRET_KEY,
                'signature': signature,
            }
        )
    )

    r.headers['Authorization'] = signature

    return r.prepare()


def _get_signature(
        method,
        path,
        query_string,
        timestamp,
        body
):
    canonical_request = '\n'.join([
        method,
        path,
        query_string,
        timestamp.strftime(TIMESTAMP_FORMAT),
        hashlib.sha512(body.encode('utf-8')).hexdigest()
    ])

    canonical_request_hash = hashlib.sha512(canonical_request.encode('utf-8')).hexdigest()

    return hmac.new(SECRET_KEY.encode('utf-8'), canonical_request_hash.encode('utf-8'), hashlib.sha512).hexdigest()


if __name__ == '__main__':
    unittest.main()
