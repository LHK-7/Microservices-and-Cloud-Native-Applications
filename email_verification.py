import json
import jwt

import boto3
import logging
from botocore.exceptions import ClientError

# Replace sender@example.com with your "From" address.
# This address must be verified with Amazon SES.
#SENDER = "Donald F. Ferguson <dff@cs.columbia.edu>"
SENDER = "Info <ryliegao@gmail.com>"
LINK = "https://ebvcfzzsg1.execute-api.us-east-1.amazonaws.com/test/verifyemail"
ENDPOINT = "http://127.0.0.1:5000"

# Specify a configuration set. If you do not want to use a configuration
# set, comment the following variable, and the 
# ConfigurationSetName=CONFIGURATION_SET argument below.
CONFIGURATION_SET = "ConfigSet"

# If necessary, replace us-west-2 with the AWS Region you're using for Amazon SES.
AWS_REGION = "us-east-1"
ACCESS_KEY = '' # DO NOT expose keys to public
SECRET_KEY = ''

# The subject line for the email.
SUBJECT = "Cool message from Don!!!"

# The email body for recipients with non-HTML email clients.
BODY_TEXT = ("Amazon SES Test (Python)\r\n"
             "This email was sent with Amazon SES using the "
             "AWS SDK for Python (Boto)."
            )

# The HTML body of the email.
BODY_HTML = """<html>
<head></head>
<body>
  <h1>Amazon SES Test (SDK for Python)</h1>
  <p>This email was sent with
    <a href='https://aws.amazon.com/ses/'>Amazon SES</a> using the
    <a href='https://aws.amazon.com/sdk-for-python/'>
      AWS SDK for Python (Boto)</a>.</p>
      <p>Link: {}?token={}</p>
      <form action="http://google.com">
        <input type="submit" value="Go to Google" />
    </form>
</body>
</html>
            """            

# The character encoding for the email.
CHARSET = "UTF-8"


# Create a new SES resource and specify a region.
client = boto3.client('ses',
    region_name=AWS_REGION,
    aws_access_key_id=ACCESS_KEY,
    aws_secret_access_key=SECRET_KEY
)

_secret = "secret"
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger()
logger.setLevel(level=logging.DEBUG)

# Try to send the email.
def send_email(em):
    try:
        logger.info("em = " + em)

        tok = jwt.encode({'email': em}, key=_secret).decode() # type: string
        logger.info("Encoded = " + str(tok))

        #Provide the contents of the email.
        response = client.send_email(
            Destination={
                'ToAddresses': [
                    em
                ],
            },
            Message={
                'Body': {
                    'Html': {
                        'Charset': CHARSET,
                        'Data': BODY_HTML.format(LINK, tok),
                    },
                    'Text': {
                        'Charset': CHARSET,
                        'Data': BODY_TEXT,
                    },
                },
                'Subject': {
                    'Charset': CHARSET,
                    'Data': SUBJECT,
                },
            },
            Source=SENDER
            # If you are not using a configuration set, comment or delete the
            # following line
            #ConfigurationSetName=CONFIGURATION_SET,
            )
    # Display an error if something goes wrong. 
    except ClientError as e:
        logger.info(e.response['Error']['Message'])
    else:
        logger.info("Email sent! Message ID:"),
        logger.info(response['MessageId'])

def handle_sns_event(records):

    sns_event = records[0]['Sns']
    topic_arn = sns_event.get("TopicArn", None)
    topic_subject = sns_event.get("Subject", None)
    topic_msg = sns_event.get("Message", None)

    print("SNS Subject = ", topic_subject)
    if topic_msg:
        json_msg = None
        try:
            json_msg = json.loads(json.loads(topic_msg))
            print("Message = ", json.dumps(json_msg, indent=2))
        except:
            print("Could not parse message.")

        em = json_msg["customers_email"]
        send_email(em)

def handle_api_event(token):
    decoded = jwt.decode(token.encode(), key=_secret) # type: dict
    email = decoded["email"] # type: str
    
    # update status PENDING -> ACTIVE
    URL = str(ENDPOINT + "/api/user/" + email)
    r = requests.put(url = URL) 
    print(r)


def lambda_handler(event, context):
    # Log the received event
    logger.info("\nEvent = " + json.dumps(event, indent=2) + "\n")
    
    # Parse the event
    records = event.get("Records", None)
    method = event.get("httpMethod", None)
    token = event.get("token", None) # string
    
    # Handle the event
    if records:
        logger.info("I got an SNS event.")
        handle_sns_event(records)
    elif token:
        logger.info("I got an API Gateway event.")
        handle_api_event(token)
    else:
        logger.info("Not sure what I got. Let it be.")

    return {
        "statusCode": 200,
        "body": json.dumps('Hello from Lambda!')
    }

