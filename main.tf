####################
# VARIABLES
####################

variable "aws_access_key" {}
variable "aws_secret_key" {}
# variable "private_key_path" {}
# variable "key_name" {}
# variable "admin_username" {}
# variable "admin_password" {}
variable "region" {
  default = "us-east-1"
}

####################
# PROVIDERS
####################

provider "aws" {
  access_key = var.aws_access_key
  secret_key = var.aws_secret_key
  region = var.region
}

####################
# DATA
####################

# define a zip archive
data "archive_file" "web-monitor-zip" {
  type        = "zip"
  output_path = "/tmp/web-monitor.zip"
  source {
    content  = <<EOF
import os
from datetime import datetime
from urllib.request import Request, urlopen

SITE = os.environ['site']  # URL of the site to check, stored in the site environment variable
EXPECTED = os.environ['expected']  # String expected to be on the page, stored in the expected environment variable


def validate(res):
    '''Return False to trigger the canary

    Currently this simply checks whether the EXPECTED string is present.
    However, you could modify this to perform any number of arbitrary
    checks on the contents of SITE.
    '''
    return EXPECTED in res


def lambda_handler(event, context):
    print('Checking {} at {}...'.format(SITE, event['time']))
    try:
        req = Request(SITE, headers={'User-Agent': 'AWS Lambda'})
        if not validate(str(urlopen(req).read())):
            raise Exception('Validation failed')
    except:
        print('Check failed!')
        raise
    else:
        print('Check passed!')
        return event['time']
    finally:
        print('Check complete at {}'.format(str(datetime.now())))
EOF
    filename = "lambda_function.py"
  }
}

resource "aws_iam_role" "web-monitor-role" {
  name = "web-monitor-role"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

# See also the following AWS managed policy: AWSLambdaBasicExecutionRole
resource "aws_iam_policy" "web-monitor-logging" {
  name        = "lambda_logging"
  path        = "/"
  description = "IAM policy for logging from a lambda"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "arn:aws:logs:*:*:*",
      "Effect": "Allow"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "web-monitor-logs" {
  role       = aws_iam_role.web-monitor-role.name
  policy_arn = aws_iam_policy.web-monitor-logging.arn
}

resource "aws_lambda_function" "web-monitor-inline" {
  function_name    = "web-monitor-function"
  role             = aws_iam_role.web-monitor-role.arn
  handler          = "lambda_function.lambda_handler"
  runtime          = "python3.7"
  filename         = data.archive_file.web-monitor-zip.output_path
  source_code_hash = data.archive_file.web-monitor-zip.output_base64sha256

  environment {
    variables = {
      site = "https://www.amazon.com"
      expected = "Amazon"
    }
  }
}

resource "aws_cloudwatch_log_group" "web-monitor-log-group" {
  name              = "/aws/lambda/web-monitor-function"
  retention_in_days = 14
}
