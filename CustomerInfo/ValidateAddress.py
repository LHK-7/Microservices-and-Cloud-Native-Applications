inin = {
    "street_line": "1211 S Coach Dr",
    "street_line_2": "APT #30",
    "city": "Catalina",
    "state": "AZ"
}

auth_id = "8715bcc7-e3d8-b3b4-ed1f-c7485e2d6002"
auth_token = "vSQrfCmQIGHIW0WTn9J7"
street_line = inin['street_line']
street2 = inin['street_line_2']
city = inin['city']
state = inin['state']

s = "https://us-street.api.smartystreets.com/street-address?auth-id=" + auth_id + "&auth-token=" + auth_token + "&candidates=10&street=" + street_line + "&city=" + city + "&state=" + state + "&zipcode=&match=invalid&street2=" + street2

ns = s.replace(' ', "%20").replace('#', '%23')

print(ns)
