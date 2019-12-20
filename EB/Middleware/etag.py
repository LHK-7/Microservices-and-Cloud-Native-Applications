import hashlib


def to_etag(profile_data):
    datastring = ""
    datastring = datastring + profile_data["display_name"] + profile_data["home_phone"] + profile_data["work_phone"] + profile_data["address_line_1"] + \
                 profile_data["address_line_2"] + profile_data["city"] + profile_data["state"]
    m = hashlib.sha256()
    m.update(str(datastring).encode('utf-8'))
    return m.hexdigest()
