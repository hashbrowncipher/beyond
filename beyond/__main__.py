"""An AWS Python Pulumi program"""
import json

import pulumi
from pulumi_random import RandomPassword
from pulumi_random import RandomString
import pulumi_aws as aws
from pulumi_aws import iam
from pulumi_aws import lambda_
from pulumi_aws import s3
from pulumi_aws import cloudfront

useast1 = aws.Provider("useast1", region="us-east-1")

config = pulumi.Config()

bucket_name = RandomString("bucket", length=16, special=False, upper=False)

# log_2(62^22) is 131 bits of entropy
hmac_secret = RandomPassword("hmac_secret", length=22, special=False)


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


bucket = s3_bucket("bucket", bucket_name)


def make_function_code(hmac_secret):
    config = dict(hmac_secret=hmac_secret)
    code = "var config = {};\n".format(json.dumps(config))
    code += open("verify-jwt.js", "r").read()
    return code


verifier = cloudfront.Function(
    "verifier",
    publish=True,
    runtime="cloudfront-js-1.0",
    code=hmac_secret.result.apply(make_function_code),
)


def make_archive(hmac_secret):
    config_ini = pulumi.StringAsset(
        f"""\
[default]
oidc_host = dev-20336771.okta.com
jwks_uri = {config.require("jwks_uri")}
token_uri = {config.require("token_uri")}
client_id = {config.require("client_id")}
client_secret = {config.require("client_secret")}
hmac_secret = {hmac_secret}
"""
    )

    return pulumi.AssetArchive(
        {
            ".": pulumi.FileArchive("./package"),
            "config.ini": config_ini,
            "lambda_function.py": pulumi.FileAsset("./issuejwt.py"),
        }
    )


def make_issuer():
    role = iam.Role(
        "lambda",
        assume_role_policy=arp(["lambda.amazonaws.com", "edgelambda.amazonaws.com"]),
    )

    # TODO: don't use lambda@edge for this?
    return lambda_.Function(
        "issuer",
        pulumi.ResourceOptions(provider=useast1),
        role=role.arn,
        runtime="python3.9",
        handler="lambda_function.lambda_handler",
        code=hmac_secret.result.apply(make_archive),
        publish=True,
    )


issuer = make_issuer()


cloudfront.Distribution(
    "internal-services",
    origins=[
        cloudfront.DistributionOriginArgs(
            domain_name=bucket.bucket_regional_domain_name,
            origin_id="s3",
        )
    ],
    enabled=True,
    restrictions=cloudfront.DistributionRestrictionsArgs(
        geo_restriction=cloudfront.DistributionRestrictionsGeoRestrictionArgs(
            restriction_type="none"
        )
    ),
    price_class="PriceClass_100",
    ordered_cache_behaviors=[
        cloudfront.DistributionOrderedCacheBehaviorArgs(
            path_pattern="/auth",
            allowed_methods=[
                "GET",
                "HEAD",
                "OPTIONS",
            ],
            cached_methods=[
                "GET",
                "HEAD",
                "OPTIONS",
            ],
            target_origin_id="s3",
            lambda_function_associations=[
                cloudfront.DistributionOrderedCacheBehaviorLambdaFunctionAssociationArgs(
                    event_type="viewer-request",
                    lambda_arn=issuer.qualified_arn,
                    include_body=False,
                )
            ],
            forwarded_values=cloudfront.DistributionOrderedCacheBehaviorForwardedValuesArgs(
                query_string=False,
                cookies=cloudfront.DistributionOrderedCacheBehaviorForwardedValuesCookiesArgs(
                    forward="none",
                ),
            ),
            viewer_protocol_policy="redirect-to-https",
        )
    ],
    default_cache_behavior=cloudfront.DistributionDefaultCacheBehaviorArgs(
        allowed_methods=[
            "DELETE",
            "GET",
            "HEAD",
            "OPTIONS",
            "PATCH",
            "POST",
            "PUT",
        ],
        cached_methods=[
            "GET",
            "HEAD",
        ],
        target_origin_id="s3",
        function_associations=[
            cloudfront.DistributionDefaultCacheBehaviorFunctionAssociationArgs(
                event_type="viewer-request",
                function_arn=verifier.arn,
            )
        ],
        forwarded_values=cloudfront.DistributionDefaultCacheBehaviorForwardedValuesArgs(
            query_string=True,
            cookies=cloudfront.DistributionDefaultCacheBehaviorForwardedValuesCookiesArgs(
                forward="none",
            ),
        ),
        viewer_protocol_policy="redirect-to-https",
        min_ttl=0,
        default_ttl=0,
        max_ttl=0,
    ),
    viewer_certificate=cloudfront.DistributionViewerCertificateArgs(
        cloudfront_default_certificate=True,
    ),
    wait_for_deployment=False,
)
