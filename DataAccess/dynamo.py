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
        "address_line_1": {
            "S": str(address['components']['primary_number'] + " "
                     + address['components']['street_name'] + " "
                     + address['components']['street_suffix'])
        }
    }
    if 'secondary_number' in address['components']:
        item.update({
            "address_line_2": {
                "S": str(address['components']['secondary_designator'] + " "
                         + address['components']['secondary_number'])
            }
        })
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
    if 'Item' not in response:
        return False
    else:
        address = {
            "address_line_1": response['Item']['address_line_1']['S'],
            "city": response['Item']['city']['S'],
            "state": response['Item']['state']['S']
        }
        if 'address_line_2' in response['Item']:
            address['address_line_2'] = response['Item']['address_line_2']['S']
        else:
            address['address_line_2'] = ""
    return address


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


# Test.
# Valid Response.
# print(json.dumps(getAddress("995162669610"), indent=4))
# {
#     "Item": {
#         "city": {
#             "S": "Anchorage"
#         },
#         "zipcode": {
#             "S": "99516"
#         },
#         "address_id": {
#             "S": "995162669610"
#         },
#         "state": {
#             "S": "AK"
#         },
#         "street": {
#             "S": "13161 Brayton Dr Apt 30"
#         }
#     },
#     "ConsumedCapacity": {
#         "TableName": "address",
#         "CapacityUnits": 0.5
#     },
#     "ResponseMetadata": {
#         "RequestId": "HFMLRCAATFM33725QSIPAVOPLFVV4KQNSO5AEMVJF66Q9ASUAAJG",
#         "HTTPStatusCode": 200,
#         "HTTPHeaders": {
#             "server": "Server",
#             "date": "Sun, 08 Dec 2019 16:53:29 GMT",
#             "content-type": "application/x-amz-json-1.0",
#             "content-length": "216",
#             "connection": "keep-alive",
#             "x-amzn-requestid": "HFMLRCAATFM33725QSIPAVOPLFVV4KQNSO5AEMVJF66Q9ASUAAJG",
#             "x-amz-crc32": "1411731111"
#         },
#         "RetryAttempts": 0
#     }
# }

# Invalid Response.
# print(json.dumps(getAddress("123"), indent=4))
# {
#     "ConsumedCapacity": {
#         "TableName": "address",
#         "CapacityUnits": 0.5
#     },
#     "ResponseMetadata": {
#         "RequestId": "01TADU5CNLSI0BB71UDNEE0RLRVV4KQNSO5AEMVJF66Q9ASUAAJG",
#         "HTTPStatusCode": 200,
#         "HTTPHeaders": {
#             "server": "Server",
#             "date": "Sun, 08 Dec 2019 16:55:47 GMT",
#             "content-type": "application/x-amz-json-1.0",
#             "content-length": "64",
#             "connection": "keep-alive",
#             "x-amzn-requestid": "01TADU5CNLSI0BB71UDNEE0RLRVV4KQNSO5AEMVJF66Q9ASUAAJG",
#             "x-amz-crc32": "227533139"
#         },
#         "RetryAttempts": 0
#     }
# }
