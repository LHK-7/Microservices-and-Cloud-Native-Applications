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
    # print(json.dumps(response.json(), indent=4))
    return response.json()


# test_input = {
#     "street_line": "1211 S Coach Dr",
#     "street_line_2": "APT #30",
#     "city": "Catalina",
#     "state": "AZ"
# }
#
# validate_address(test_input)
