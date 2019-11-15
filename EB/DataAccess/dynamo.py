import boto3
import json
import uuid

# AWS Credentials: dynamoUser
ACCESS_KEY = 'AKIAZ7JA4ZXTGY32YRXN'
SECRET_KEY = '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'
REGION = 'us-east-1'


def reformat(address):
    # type(address): dict
    item = {
        "address_id": {
            "S": str(uuid.uuid4())
        },
        "zipcode": {
            "S": address["zipcode"]
        },
        "state": {
            "S": address["state"]
        },
        "city": {
            "S": address["city"]
        },
        "street": {
            "S": address["street"]
        },
        "street2": {
            "S": address["street2"]
        }
    }
    return item


def addAddress(address):
    global ACCESS_KEY
    global SECRET_KEY
    global REGION
    client = boto3.client('dynamodb', aws_access_key_id=ACCESS_KEY, aws_secret_access_key=SECRET_KEY,
                          region_name=REGION)
    item = reformat(address)
    response = client.put_item(
        Item=item,
        ReturnConsumedCapacity='TOTAL',
        TableName='address',
    )
    return item["address_id"]["S"]


def getAddress(address_id):
    global ACCESS_KEY
    global SECRET_KEY
    global REGION
    client = boto3.client('dynamodb', aws_access_key_id=ACCESS_KEY, aws_secret_access_key=SECRET_KEY,
                          region_name=REGION)
    response = client.get_item(
        Item="item",
        ReturnConsumedCapacity='TOTAL',
        TableName='address'
    )
    print("response = ", response)
    return response


def updateAddress(address, address_id):
    global ACCESS_KEY
    global SECRET_KEY
    global REGION
    client = boto3.client('dynamodb', aws_access_key_id=ACCESS_KEY, aws_secret_access_key=SECRET_KEY,
                          region_name=REGION)
    response = client.put_item(
        Item="item",
        ReturnConsumedCapacity='TOTAL',
        TableName='address'
    )
    print("response = ", response)
    return response
