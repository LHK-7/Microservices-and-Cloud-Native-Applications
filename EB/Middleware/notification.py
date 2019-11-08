import boto3
import json
ACCESS_KEY = ''
SECRET_KEY = ''
REGION = 'us-east-1'
def publish_it(msg):

    client = boto3.client('sns', aws_access_key_id=ACCESS_KEY, aws_secret_access_key=SECRET_KEY,
                          region_name = REGION)
    txt_msg = json.dumps(msg)

    client.publish(TopicArn='arn:aws:sns:us-east-1:685653151206:topic1',
                   Message=txt_msg)
