########################################################################################################################
# We are using REST API to call SmartyStreet Address Validation Service here. There is another way (python sdk).
# An example is as follow.
# https://github.com/smartystreets/smartystreets-python-sdk/blob/master/examples/us_street_single_address_example.py
########################################################################################################################
import requests
import json


def validate_address(input_address):
    auth_id = "8715bcc7-e3d8-b3b4-ed1f-c7485e2d6002"
    auth_token = "vSQrfCmQIGHIW0WTn9J7"
    street_line = input_address['street_line']
    street2 = input_address['street_line_2']
    city = input_address['city']
    state = input_address['state']
    tmp = "https://us-street.api.smartystreets.com/street-address?auth-id=" + auth_id + "&auth-token=" + auth_token \
          + "&candidates=10&street=" + street_line + "&city=" + city + "&state=" + state + "&zipcode=&match=invalid" \
          + "&street2=" + street2
    url = tmp.replace(' ', "%20").replace('#', '%23')
    # print(url)
    response = requests.get(url)
    # print(json.dumps(response.json()[0], indent=4))
    return response.json()[0]

#
# test_input_valid = {
#     "street_line": "13161 Brayton Drive",
#     "street_line_2": "APT #30",
#     "city": "Anchorage",
#     "state": "AK"
# }
#
# validate_address(test_input_valid)

# response =
# {
#     "input_index": 0,
#     "candidate_index": 0,
#     "delivery_line_1": "13161 Brayton Dr Apt 30",
#     "last_line": "Anchorage AK 99516-2669",
#     "delivery_point_barcode": "995162669610",
#     "components": {
#         "primary_number": "13161",
#         "street_name": "Brayton",
#         "street_suffix": "Dr",
#         "secondary_number": "30",
#         "secondary_designator": "Apt",
#         "city_name": "Anchorage",
#         "default_city_name": "Anchorage",
#         "state_abbreviation": "AK",
#         "zipcode": "99516",
#         "plus4_code": "2669",
#         "delivery_point": "61",
#         "delivery_point_check_digit": "0"
#     },
#     "metadata": {
#         "record_type": "S",
#         "zip_type": "Standard",
#         "county_fips": "02020",
#         "county_name": "Anchorage",
#         "carrier_route": "C014",
#         "congressional_district": "AL",
#         "rdi": "Commercial",
#         "elot_sequence": "0001",
#         "elot_sort": "A",
#         "latitude": 61.10206,
#         "longitude": -149.84258,
#         "precision": "Zip9",
#         "time_zone": "Alaska",
#         "utc_offset": -9,
#         "dst": true
#     },
#     "analysis": {
#         "dpv_match_code": "S",
#         "dpv_footnotes": "AACC",
#         "dpv_cmra": "N",
#         "dpv_vacant": "N",
#         "active": "Y",
#         "footnotes": "N#"
#     }
# }


# test_input_invalid = {
#     "street_line": "416848645 ss",
#     "street_line_2": "APT #30",
#     "city": "eds",
#     "state": "015d"
# }
#
# validate_address(test_input_invalid)

# response =
# {
#     "input_index": 0,
#     "candidate_index": 0,
#     "delivery_line_1": "416848645 Ss",
#     "delivery_line_2": "Apt #30",
#     "last_line": "Eds",
#     "components": {
#         "primary_number": "416848645",
#         "street_name": "SS",
#         "secondary_number": "30",
#         "secondary_designator": "Apt",
#         "city_name": "Eds"
#     },
#     "metadata": {
#         "precision": "Unknown"
#     },
#     "analysis": {
#         "dpv_footnotes": "A1",
#         "footnotes": "C#"
#     }
# }
