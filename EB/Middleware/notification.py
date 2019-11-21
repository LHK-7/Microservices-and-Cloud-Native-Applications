import boto3
import json
import os


# AWS Credentials: dynamoUser
sns = json.loads(os.environ['sns'])
ACCESS_KEY = sns['ACCESS_KEY']
SECRET_KEY = sns['SECRET_KEY']
REGION = sns['REGION']


def publish_it(msg):
    client = boto3.client('sns', aws_access_key_id=ACCESS_KEY, aws_secret_access_key=SECRET_KEY,
                          region_name=REGION)
    txt_msg = json.dumps(msg)

    client.publish(TopicArn='arn:aws:sns:us-east-1:685653151206:topic1',
                   Message=txt_msg)
