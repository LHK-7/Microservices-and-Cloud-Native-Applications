import boto3
import json
<<<<<<< Updated upstream


def publish_it(msg):

    client = boto3.client('sns')
    txt_msg = json.dumps(msg)

    client.publish(TopicArn="arn:aws:sns:us-east-1:832720255830:E6156CustomerChange",
                   Message=txt_msg)
=======
ACCESS_KEY = ''
SECRET_KEY = ''
REGION = 'us-east-1'
def publish_it(msg):

    client = boto3.client('sns', aws_access_key_id=ACCESS_KEY, aws_secret_access_key=SECRET_KEY,
                          region_name = REGION)
    txt_msg = json.dumps(msg)

    client.publish(TopicArn='arn:aws:sns:us-east-1:685653151206:topic1',
                   Message=txt_msg)
>>>>>>> Stashed changes
