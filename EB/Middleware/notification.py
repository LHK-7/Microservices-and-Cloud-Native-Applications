import json

import boto3


def publish_it(msg):

    client = boto3.client('sns',
                          region_name='us-east-1',
                          aws_access_key_id='AKIAJKMANSAMMSGXDOWA',
                          aws_secret_access_key='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',
                          )
    txt_msg = json.dumps(msg)

    response = client.publish(TopicArn="arn:aws:sns:us-east-1:685653151206:topic1",
                   Message=txt_msg)
    print("response is:", response)
