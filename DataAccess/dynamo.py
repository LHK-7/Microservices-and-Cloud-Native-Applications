import boto3
import json
# import uuid
import os


# AWS Credentials: dynamoUser
dynamo = json.loads(os.environ['dynamo'])
ACCESS_KEY = dynamo['ACCESS_KEY']
SECRET_KEY = dynamo['SECRET_KEY']
REGION = dynamo['REGION']


def reformat(address):
    item = {
        "address_id": {
            "S": address['delivery_point_barcode']
        },
        "zipcode": {
            "S": address['components']['zipcode']
        },
        "state": {
            "S": address["components"]['state_abbreviation']
        },
        "city": {
            "S": address["components"]['city_name']
        },
        "street": {
            "S": address["delivery_line_1"]
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
        Key={
            "address_id": {
                "S": address_id
            }
        },
        ReturnConsumedCapacity='TOTAL',
        TableName='address'
    )
    return response


def updateAddress(address, address_id):
    global ACCESS_KEY
    global SECRET_KEY
    global REGION
    client = boto3.client('dynamodb', aws_access_key_id=ACCESS_KEY, aws_secret_access_key=SECRET_KEY,
                          region_name=REGION)

    response = client.update_item(
        Key={
            "address_id": {
                "S": address_id
            }
        },
        ExpressionAttributeNames={
            "#C": "zipcode",
            "#D": "state",
            "#E": "city",
            "#F": "street"
        },
        ExpressionAttributeValues={
            ':c': {
                'S': address["zipcode"],
            },
            ':d': {
                'S': address["state"],
            },
            ':e': {
                'S': address["city"],
            },
            ':f': {
                'S': address["street"],
            },
        },
        ReturnValues='ALL_NEW',
        TableName='address',
        UpdateExpression='SET #C = :c, #D = :d, #E = :e, #F = :f',
    )
    return response
