import json
import jwt
import requests
# from requests import Request, Session
import boto3
import logging
from botocore.exceptions import ClientError

# This address must be verified with Amazon SES.
# Format: SENDER = "Donald F. Ferguson <dff@cs.columbia.edu>"
SENDER = "Info <ryliegao@gmail.com>"

# API Gateway
LINK = "https://ebvcfzzsg1.execute-api.us-east-1.amazonaws.com/test/verifyemail"

# Validation RESTful server (update user status)
ENDPOINT = "http://e6156yeah.us-east-2.elasticbeanstalk.com/"

# Specify a configuration set. If you do not want to use a configuration
# set, comment the following variable, and the
# ConfigurationSetName=CONFIGURATION_SET argument below.
CONFIGURATION_SET = "ConfigSet"

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
                      # region_name=AWS_REGION,
                      # aws_access_key_id=ACCESS_KEY,
                      # aws_secret_access_key=SECRET_KEY
                      )

# The secret key for jwt encoding.
_secret = "secret"

# Setup logging.
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger()
logger.setLevel(level=logging.DEBUG)


# Try to send the email.
def send_email(em):
    try:
        logger.info("em = " + em)

        tok = jwt.encode({'email': em}, key=_secret).decode()
        logger.info("Encoded = " + str(tok))

        # Provide the contents of the email.
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
            # ConfigurationSetName=CONFIGURATION_SET,
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
    try:
        decoded = jwt.decode(token.encode(), key=_secret)  # type: dict
        email = decoded["email"]  # type: str

        # Call RESTful microservice. Validate the token and Update user status PENDING -> ACTIVE.
        URL = str(ENDPOINT + "/api/user/" + email)
        headers = {"pass": "sL36KjRf5oAc79ifhPJAz1bqi03WQPCC"}
        r = requests.put(url=URL, headers=headers)
        print("r = ", r)
        # print("statusCode = " + str(r.status_code))
        return r.content.decode()
    except:
        logger.error("\nError occurs when handling api event.\n")
        return "0"


def lambda_handler(event, context):
    logger.info("\nEvent = " + json.dumps(event, indent=2) + "\n")

    records = event.get("Records", None)
    method = event.get("httpMethod", None)
    token = event.get("token", None)  # string

    logger.info("\nRecords = " + json.dumps(records, indent=2) + "\n")
    logger.info("\nhttpMethod = " + json.dumps(method, indent=2) + "\n")
    logger.info("\ntoken = " + json.dumps(token, indent=2) + "\n")

    if records:
        logger.info("I got an SNS event.")
        handle_sns_event(records)
    elif token:
        logger.info("I got an API Gateway event.")
        res = handle_api_event(token)
        logger.info("res = " + res)
        # REDIRECT
        if res == "1":
            response = {'location': 'https://www.youtube.com/watch?v=WS6jCdLFjrU'}
        elif res == "None":
            response = {'location': 'https://www.uptrends.com/support/kb/account-access/already-activated'}
        else:
            response = {'location': 'https://www.youtube.com/watch?v=t3otBjVZzT0'}
        return response

    else:
        logger.info("Not sure what I got. Let it be.")

    return {
        "statusCode": 200,
        "body": json.dumps('Hello from Lambda!')
    }