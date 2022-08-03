"""An AWS Python Pulumi program"""
import json

import pulumi
from pulumi import Output
from pulumi_random import RandomString
import pulumi_aws as aws
from pulumi_aws import iam
from pulumi_aws import lambda_
from pulumi_aws import s3
from pulumi_aws import dynamodb

useast1 = aws.Provider("useast1", region="us-east-1")

config = pulumi.Config()

bucket_name = RandomString("bucket", length=16, special=False, upper=False)


def arp(allowed_services):
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "sts:AssumeRole",
                    "Effect": "Allow",
                    "Sid": "",
                    "Principal": {
                        "Service": allowed_services,
                    },
                }
            ],
        }
    )


def s3_bucket(identifier, name):
    bucket = s3.BucketV2(
        identifier,
        bucket=name,
    )

    s3.BucketAclV2(identifier, bucket=name, acl="private")

    s3.BucketServerSideEncryptionConfigurationV2(
        identifier,
        bucket=name,
        rules=[
            s3.BucketServerSideEncryptionConfigurationV2RuleArgs(
                apply_server_side_encryption_by_default=s3.BucketServerSideEncryptionConfigurationV2RuleApplyServerSideEncryptionByDefaultArgs(
                    sse_algorithm="AES256",
                ),
                bucket_key_enabled=True,
            )
        ],
    )

    s3.BucketPublicAccessBlock(
        identifier,
        bucket=name,
        block_public_acls=True,
        block_public_policy=True,
        ignore_public_acls=True,
        restrict_public_buckets=True,
    )

    return bucket


def output_kwargs(fn):
    def wrapper(args):
        return fn(**args)

    return wrapper


@output_kwargs
def make_archive(tokens_table, bucket):
    config_ini = pulumi.StringAsset(
        f"""\
[default]
oidc_host = dev-20336771.okta.com
jwks_uri = {config.require("jwks_uri")}
token_uri = {config.require("token_uri")}
client_id = {config.require("client_id")}
client_secret = {config.require("client_secret")}
tokens_table = {tokens_table}
bucket = {bucket}
"""
    )

    return pulumi.AssetArchive(
        {
            ".": pulumi.FileArchive("./package"),
            "config.ini": config_ini,
            "lambda_function.py": pulumi.FileAsset("./issuejwt.py"),
        }
    )


def _iam_policy(statements):
    return json.dumps(dict(Version="2012-10-17", Statement=statements))


@output_kwargs
def _lambda_policy(*, tokens_arn, bucket_arn):
    statements = [
        dict(
            Action=["dynamodb:PutItem", "dynamodb:GetItem"],
            Effect="Allow",
            Resource=[tokens_arn],
        ),
        dict(
            Effect="Allow",
            Action="logs:CreateLogGroup",
            Resource="arn:aws:logs:us-east-1:624142562444:*",
        ),
        dict(
            Effect="Allow",
            Action=[
                "logs:CreateLogStream",
                "logs:PutLogEvents",
            ],
            Resource=[
                "arn:aws:logs:us-east-1:624142562444:log-group:/aws/lambda/issuer-*:*"
            ],
        ),
        dict(
            Effect="Allow",
            Action=["s3:GetObject", "s3:ListBucket"],
            Resource=[
                bucket_arn,
                bucket_arn + "/*",
            ],
        ),
    ]
    return _iam_policy(statements)


def make_issuer(tokens, bucket):
    outputs = Output.all(tokens_arn=tokens.arn, bucket_arn=bucket.arn)
    role = iam.Role(
        "lambda",
        assume_role_policy=arp(["lambda.amazonaws.com"]),
        inline_policies=[
            aws.iam.RoleInlinePolicyArgs(
                name="policy",
                policy=outputs.apply(_lambda_policy),
            )
        ],
    )

    function = lambda_.Function(
        "issuer",
        role=role.arn,
        runtime="python3.9",
        # arm64 is noticeably slower, and not in a small way.
        # it's the difference between 500 microseconds and 500 milliseconds
        architectures=["x86_64"],
        handler="lambda_function.lambda_handler",
        timeout=60,
        code=Output.all(tokens_table=tokens.id, bucket=bucket.bucket).apply(
            make_archive
        ),
        publish=True,
    )

    lambda_.FunctionUrl(
        "issuer", function_name=function.name, authorization_type="NONE"
    )


bucket = s3_bucket("bucket", bucket_name)

s3.BucketObject(
    "test",
    key="test",
    bucket=bucket.id,
    content="Hi there!\n",
)

tokens = dynamodb.Table(
    "tokens2",
    name="tokens",
    attributes=[
        dynamodb.TableAttributeArgs(
            name="hashed_token",
            type="B",
        )
    ],
    billing_mode="PAY_PER_REQUEST",
    hash_key="hashed_token",
)
issuer = make_issuer(tokens, bucket)
