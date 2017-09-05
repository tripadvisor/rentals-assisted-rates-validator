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


POSSIBLE_CURRENCIES = {'AUD', 'CAD', 'CHF', 'EUR', 'GBP', 'SEK', 'THB', 'USD'}
MIN_STAY_VIOLATION = 'MIN_STAY_VIOLATION'
TURNOVER_VIOLATION = 'TURNOVER_VIOLATION'
DATE_RANGE_UNAVAILABLE = 'DATE_RANGE_UNAVAILABLE'
VIOLATION_CODES = {MIN_STAY_VIOLATION, TURNOVER_VIOLATION, DATE_RANGE_UNAVAILABLE}
TURNOVER_DAYS = {'MONDAY', 'TUESDAY', 'WEDNESDAY', 'THURSDAY', 'FRIDAY', 'SATURDAY', 'SUNDAY'}
ERROR_REASONS = {'PROPERTY_INACTIVE', 'DATE_RANGE_INVALID', 'PARTY_SIZE_INVALID', 'RATE_UNAVAILABLE', 'OTHER'}

# TODO: Update the following variables to match your system
SECRET_KEY = 'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789'
BASE_URL = 'https://example.com'
PATH = '/path/to/your/endpoint'
EXTERNAL_LISTING_REFERENCE = 'abc123'

CLIENT_NAME = 'tripadvisor-vr'
TIMESTAMP_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
SIGNATURE_FORMAT = "VRS-HMAC-SHA512 timestamp={timestamp}, client={client}, signature={signature}"
QUERY_STRING_FORMAT = 'guests={guests}&externalListingReference={external_listing_reference}&arrival={arrival}&departure={departure}&requestId={request_id}'

logging.basicConfig(
    format='%(asctime)s %(levelname)s %(funcName)s %(message)s',
    level=logging.INFO
)

QueryParameters = collections.namedtuple(
    'QueryParameters',
    [
        'guests',
        'external_listing_reference',
        'arrival',
        'departure',
    ]
)

# TODO: Update the following test inputs to match your system
# Comment out a top-level key, value pair to skip that particular test
TEST_CASES = {
    'successful_response': QueryParameters(
        guests=7,
        external_listing_reference=EXTERNAL_LISTING_REFERENCE,
        arrival='2018-07-01',
        departure='2018-08-01',
    ),
    'min_stay_violation': QueryParameters(
        guests=16,
        external_listing_reference=EXTERNAL_LISTING_REFERENCE,
        arrival='2018-08-01',
        departure='2018-08-05',
    ),
    'date_range_unavailable_violation': QueryParameters(
        guests=17,
        external_listing_reference=EXTERNAL_LISTING_REFERENCE,
        arrival='2018-08-01',
        departure='2018-08-02',
    ),
    'turnday_violation': QueryParameters(
        guests=18,
        external_listing_reference=EXTERNAL_LISTING_REFERENCE,
        arrival='2018-08-02',
        departure='2018-08-03',
    ),
    'property_inactive_error': QueryParameters(
        guests=10,
        external_listing_reference=EXTERNAL_LISTING_REFERENCE,
        arrival='2018-08-03',
        departure='2018-08-04',
    ),
    'date_range_invalid_error': QueryParameters(
        guests=11,
        external_listing_reference=EXTERNAL_LISTING_REFERENCE,
        arrival='2018-08-03',
        departure='2018-08-04',
    ),
    'party_size_invalid_error': QueryParameters(
        guests=12,
        external_listing_reference=EXTERNAL_LISTING_REFERENCE,
        arrival='2018-08-03',
        departure='2018-08-04',
    ),
    'other_error': QueryParameters(
        guests=13,
        external_listing_reference=EXTERNAL_LISTING_REFERENCE,
        arrival='2018-08-03',
        departure='2018-08-04',
    ),
}


class AssistedRateSpecTest(unittest.TestCase):
    s = requests.Session()

    def _send_request(self, request):
        """

        :type request: requests.PreparedRequest
        :rtype: tuple[requests.Response, dict|None]
        :return: tuple[response, response body as dict, if present]

        """

        response = self.s.send(request)

        try:
            body = response.json()
        except ValueError:
            body = None

        if response.status_code == 200:
            self.validate_200_response(body)
        elif response.status_code == 400:
            self.validate_400_response(body)
        else:
            raise RuntimeError('Unexpected HTTP response code')

        return response, body

    def validate_200_response(self, body):
        self.assertIn('details', body)

        details = body['details']

        self.assertIn('baseRate', details)
        self.assertGreater(details['baseRate']['amount'], 0)
        self.assertIn(details['baseRate']['currency'], POSSIBLE_CURRENCIES)

        self.assertIn('tax', details)
        self.assertGreaterEqual(details['tax']['amount'], 0)
        self.assertIn(details['tax']['currency'], POSSIBLE_CURRENCIES)

        if 'deposit' in details:
            self.assertGreater(details['deposit']['amount'], 0)
            self.assertIn(details['deposit']['currency'], POSSIBLE_CURRENCIES)

        if 'customFees' in details:
            self.assertGreaterEqual(len(details['customFees']), 1)

            for custom_fee in details['customFees']:
                self.assertGreaterEqual(len(custom_fee['name']), 1)
                self.assertLessEqual(len(custom_fee['name']), 255)

                self.assertGreater(custom_fee['rate']['amount'], 0)
                self.assertIn(custom_fee['rate']['currency'], POSSIBLE_CURRENCIES)

        self.assertEqual(
            {'baseRate', 'tax', 'deposit', 'customFees'} | set(details.keys()),
            {'baseRate', 'tax', 'deposit', 'customFees'}
        )

        if 'eligibility' in body:
            self.assertIn('tripViolations', body['eligibility'])
            self.assertEqual(set(body['eligibility'].keys()), {'tripViolations'})

            trip_violations = body['eligibility']['tripViolations']

            self.assertGreaterEqual(len(trip_violations), 1)
            self.assertEqual(
                len(trip_violations),
                len(set([trip_violation['violationCode'] for trip_violation in trip_violations]))
            )

            for trip_violation in trip_violations:
                self.assertIn(trip_violation['violationCode'], VIOLATION_CODES)

                if trip_violation['violationCode'] == TURNOVER_VIOLATION:
                    self.assertEqual(set(trip_violation.keys()), {'violationCode', 'turnover'})
                    self.assertIn(trip_violation['turnover'], TURNOVER_DAYS)
                elif trip_violation['violationCode'] == MIN_STAY_VIOLATION:
                    self.assertEqual(set(trip_violation.keys()), {'violationCode', 'minStay'})
                    self.assertIsInstance(trip_violation['minStay'], int)
                    self.assertGreater(trip_violation['minStay'], 1)
                else:
                    self.assertEqual(set(trip_violation.keys()), {'violationCode'})

    def validate_400_response(self, body):
        self.assertIn('errors', body)

        errors = body['errors']

        self.assertGreaterEqual(len(errors), 1)

        for error in errors:
            self.assertEqual(
                {'reason', 'description'} | set(error.keys()),
                {'reason', 'description'}
            )

            self.assertIn('reason', error)
            self.assertIn(error['reason'], ERROR_REASONS)

            if 'description' in error:
                self.assertGreaterEqual(len(error['description']), 1)
                self.assertLessEqual(len(error['description']), 255)

        self.assertEqual(
            len(errors),
            len(set([e['reason'] for e in errors]))
        )

    @unittest.skipIf('successful_response' not in TEST_CASES, 'Test case not implemented')
    def test_successful_response(self):
        response, body = self._send_request(_get_request(TEST_CASES['successful_response']))

        self.assertEqual(response.status_code, 200)

    @unittest.skipIf('min_stay_violation' not in TEST_CASES, 'Test case not implemented')
    def test_min_stay_violation(self):
        response, body = self._send_request(_get_request(TEST_CASES['min_stay_violation']))

        self.assertEqual(response.status_code, 200)

        min_stay_violations = [
            v for v in body['eligibility']['tripViolations']
            if v['violationCode'] == 'MIN_STAY_VIOLATION'
        ]

        self.assertEqual(len(min_stay_violations), 1)

    @unittest.skipIf('date_range_unavailable_violation' not in TEST_CASES, 'Test case not implemented')
    def test_date_range_unavailable(self):
        response, body = self._send_request(_get_request(TEST_CASES['date_range_unavailable_violation']))

        self.assertEqual(response.status_code, 200)

        date_range_unavailable_violations = [
            v for v in body['eligibility']['tripViolations']
            if v['violationCode'] == 'DATE_RANGE_UNAVAILABLE'
        ]

        self.assertEqual(len(date_range_unavailable_violations), 1)

    @unittest.skipIf('turnday_violation' not in TEST_CASES, 'Test case not implemented')
    def test_turnday(self):
        response, body = self._send_request(_get_request(TEST_CASES['turnday_violation']))

        self.assertEqual(response.status_code, 200)

        turnover_violations = [
            v for v in body['eligibility']['tripViolations']
            if v['violationCode'] == 'TURNOVER_VIOLATION'
        ]

        self.assertEqual(len(turnover_violations), 1)

    @unittest.skipIf('property_inactive_error' not in TEST_CASES, 'Test case not implemented')
    def test_property_inactive_error(self):
        response, body = self._send_request(_get_request(TEST_CASES['property_inactive_error']))

        self.assertEqual(response.status_code, 400)

        self.assertIn('errors', body)

        property_inactive_errors = [
            v for v in body['errors']
            if v['reason'] == 'PROPERTY_INACTIVE'
        ]

        self.assertEqual(len(property_inactive_errors), 1)

    @unittest.skipIf('date_range_invalid_error' not in TEST_CASES, 'Test case not implemented')
    def test_date_range_invalid_error(self):
        response, body = self._send_request(_get_request(TEST_CASES['date_range_invalid_error']))

        self.assertEqual(response.status_code, 400)

        self.assertIn('errors', body)

        property_inactive_errors = [
            v for v in body['errors']
            if v['reason'] == 'DATE_RANGE_INVALID'
        ]

        self.assertEqual(len(property_inactive_errors), 1)

    @unittest.skipIf('party_size_invalid_error' not in TEST_CASES, 'Test case not implemented')
    def test_party_size_invalid_error(self):
        response, body = self._send_request(_get_request(TEST_CASES['party_size_invalid_error']))

        self.assertEqual(response.status_code, 400)

        self.assertIn('errors', body)

        property_inactive_errors = [
            v for v in body['errors']
            if v['reason'] == 'PARTY_SIZE_INVALID'
        ]

        self.assertEqual(len(property_inactive_errors), 1)

    @unittest.skipIf('other_error' not in TEST_CASES, 'Test case not implemented')
    def test_other_error(self):
        response, body = self._send_request(_get_request(TEST_CASES['other_error']))

        self.assertEqual(response.status_code, 400)

        self.assertIn('errors', body)

        property_inactive_errors = [
            v for v in body['errors']
            if v['reason'] == 'OTHER'
        ]

        self.assertGreaterEqual(len(property_inactive_errors), 1)


def _get_request(query_parameters):
    now = datetime.datetime.now(tz=pytz.UTC)
    body = ''

    query_string = QUERY_STRING_FORMAT.format(
        guests=query_parameters.guests,
        external_listing_reference=query_parameters.external_listing_reference,
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

    r.headers['Authorization'] = signature

    logging.info(
        "Request {}".format(json.dumps({
            'url': r.url,
            'method': r.method,
            'path': PATH,
            'query_string': query_string,
            'body': body,
            'timestamp': now.strftime(TIMESTAMP_FORMAT),
            'client': CLIENT_NAME,
            'secret': SECRET_KEY,
            'signature': signature,
        }))
    )

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
