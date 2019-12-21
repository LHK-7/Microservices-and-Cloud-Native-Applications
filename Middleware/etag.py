import hashlib


def to_etag(profile):
    home_phone, work_phone, address_line_1, address_line_2, city, state = "", "", "", "", "", ""
    entries = profile["profile_entries"]

    if entries:
        for entry in entries:
            if entry["type"] == "telephone":
                if entry["subtype"] == "home":
                    home_phone = entry["value"]
                elif entry["subtype"] == "work":
                    work_phone = entry["value"]
            elif entry["type"] == "address_line_1":
                address_line_1 = entry["value"]
            elif entry["type"] == "address_line_2":
                address_line_2 = entry["value"]
            elif entry["type"] == "city":
                city = entry["value"]
            elif entry["type"] == "state":
                state = entry["value"]

    datastring = home_phone + work_phone + address_line_1 + address_line_2 + city, state

    m = hashlib.sha256()
    m.update(str(datastring).encode('utf-8'))

    return m.hexdigest()
