"""Fixtures shared across tests.

Some of these fixtures are based on the Tableau Altimeter's test suite. For
more details, please see:

https://github.com/tableau/altimeter/blob/f8f1a2fa8b6a61390b1eb2ca30ffa29739734774/tests/integration/altimeter/aws/test_aws2n.py
"""

# pylint: disable=redefined-outer-name,unused-argument

import os
import io
import json
import uuid
import random
import zipfile
from pathlib import Path

import moto
import boto3
import pytest
from gremlin_python.process.anonymous_traversal import traversal
from gremlin_python.process.traversal import (
    T,
    Cardinality,
)

from graph_altimeter import EnvVarNotSetError, gremlin, CURRENT_UNIVERSE


TESTDATA_DIR = Path(__file__).resolve().parent / "testdata"


def get_gremlin_endpoint():
    """Returns the gremlin endpoint from the environment."""
    gremlin_endpoint = os.getenv('GREMLIN_ENDPOINT', '')
    if gremlin_endpoint == '':
        raise EnvVarNotSetError('GREMLIN_ENDPOINT')
    return gremlin_endpoint


def get_auth_mode():
    """Returns the auth mode from the environment."""
    return os.getenv('GREMLIN_AUTH_MODE', 'none')


@pytest.fixture(scope='session', autouse=True)
def init_session(aws_resources):
    """Initializes session fixtures in a given order."""


@pytest.fixture(scope='session')
def aws_credentials():
    """Mocked AWS Credentials for moto."""
    os.environ['AWS_ACCESS_KEY_ID'] = 'testing'
    os.environ['AWS_SECRET_ACCESS_KEY'] = 'testing'
    os.environ['AWS_SECURITY_TOKEN'] = 'testing'
    os.environ['AWS_SESSION_TOKEN'] = 'testing'
    os.environ['AWS_DEFAULT_REGION'] = 'us-east-1'


@pytest.fixture(scope='session')
def aws_resources(aws_credentials):
    """Creates AWS resources using moto to mock AWS."""
    # pylint: disable=too-many-locals

    # Make random operations predictable (e.g. resources ARNs, policy IDs).
    random.seed(0)

    aws_mocks = [
        moto.mock_dynamodb2(),
        moto.mock_ec2(),
        moto.mock_iam(),
        moto.mock_lambda(),
        moto.mock_s3(),
        moto.mock_sts(),
    ]

    for mock in aws_mocks:
        mock.start()

    resource_region_name = "us-east-1"

    # Delete all VPCs.
    ec2_client = boto3.client("ec2", region_name=resource_region_name)
    describe_regions_filters = [
        {
            "Name": "opt-in-status",
            "Values": ["opt-in-not-required", "opted-in"]
        }
    ]
    all_regions = ec2_client.describe_regions(
        Filters=describe_regions_filters
    )["Regions"]
    account_id = get_account_id()
    all_region_names = tuple(region["RegionName"] for region in all_regions)
    delete_vpcs(all_region_names)

    # Create S3 resources.
    bucket_1_name = "test_bucket"
    create_bucket(
        name=bucket_1_name,
        account_id=account_id,
        region_name=resource_region_name,
    )

    # Create EC2 resources.
    vpc_1_cidr = "10.0.0.0/16"
    vpc_1_id = create_vpc(
        cidr_block=vpc_1_cidr,
        region_name=resource_region_name,
    )
    subnet_1_cidr = "10.0.0.0/24"
    create_subnet(
        cidr_block=subnet_1_cidr,
        vpc_id=vpc_1_id,
        region_name=resource_region_name,
    )
    fixed_bucket_1_arn = f"arn:aws:s3:::{bucket_1_name}"
    create_flow_log(
        vpc_id=vpc_1_id,
        dest_bucket_arn=fixed_bucket_1_arn,
        region_name=resource_region_name,
    )
    ebs_volume_1_size = 128
    ebs_volume_1_az = f"{resource_region_name}a"
    create_volume(
        size=ebs_volume_1_size,
        availability_zone=ebs_volume_1_az,
        region_name=resource_region_name,
    )

    # Create IAM resources.
    policy_1_name = "test_policy_1"
    create_iam_policy(
        name=policy_1_name,
        policy_doc={
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "logs:CreateLogGroup",
                    "Resource": "*",
                },
                {
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": f"arn:aws:s3:::{bucket_1_name}"
                }
            ],
        },
    )
    role_1_name = "test_role_1"
    role_1_assume_role_policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Action": "sts:AssumeRole",
                "Effect": "Allow",
                "Principal": {
                    "Service": "lambda.amazonaws.com"
                },
                "Sid": "",
            }
        ],
    }
    role_1_description = "Test Role 1"
    role_1_max_session_duration = 3600
    role_1_arn = create_iam_role(
        name=role_1_name,
        assume_role_policy_doc=role_1_assume_role_policy_doc,
        description=role_1_description,
        max_session_duration=role_1_max_session_duration,
    )

    # Create Lambda resources.
    lambda_function_1_name = "test_lambda_function_1"
    lambda_function_1_runtime = "python3.7"
    lambda_function_1_handler = "lambda_function.lambda_handler"
    lambda_function_1_description = "Test Lambda Function 1"
    lambda_function_1_timeout = 30
    lambda_function_1_memory_size = 256
    create_lambda_function(
        name=lambda_function_1_name,
        runtime=lambda_function_1_runtime,
        role_name=role_1_arn,
        handler=lambda_function_1_handler,
        description=lambda_function_1_description,
        timeout=lambda_function_1_timeout,
        memory_size=lambda_function_1_memory_size,
        publish=False,
        region_name=resource_region_name,
    )

    # TODO: document how to generate a golden file.
    graph = None
    with open(TESTDATA_DIR / "graph.json", "rb") as graph_file:
        graph = json.loads(graph_file.read())

    data = {
        "account": account_id,
        "target_account_role": role_1_name,
        "graph": graph,
    }

    yield data

    for mock in aws_mocks:
        mock.stop()


@pytest.fixture
def g():
    """Returns the graph traversal source. It takes care of closing the gremlin
    connection after finishing the test. All vertices are deleted on both
    the setup and teardown stage of this fixture."""
    conn = gremlin.get_connection(get_gremlin_endpoint(), get_auth_mode())
    g = traversal().withRemote(conn)

    g.V().drop().iterate()

    yield g

    g.V().drop().iterate()

    conn.close()


@pytest.fixture
def universe(g):
    """Creates the current universe vertex"""
    create_universe(g, CURRENT_UNIVERSE)


def create_universe(g, universe):
    """Creates a new Altimeter ``Universe`` vertex."""
    return g \
        .addV("Universe") \
        .property(T.id, str(uuid.uuid4())) \
        .property(
                Cardinality.single,
                'namespace',
                universe.namespace
        ) \
        .property(
                Cardinality.single,
                'version',
                universe.version.int_version
        ) \
        .next()


def delete_vpcs(region_names):
    """Deletes the VPCs in the specified regions."""
    for region_name in region_names:
        regional_ec2_client = boto3.client("ec2", region_name=region_name)
        vpcs_resp = regional_ec2_client.describe_vpcs()
        vpcs = vpcs_resp.get("Vpcs", [])
        for vpc in vpcs:
            vpc_id = vpc["VpcId"]
            subnets_resp = regional_ec2_client.describe_subnets(
                Filters=[{"Name": "vpc-id", "Values": [vpc_id]}],
            )
            for subnet in subnets_resp["Subnets"]:
                subnet_id = subnet["SubnetId"]
                regional_ec2_client.delete_subnet(SubnetId=subnet_id)
            regional_ec2_client.delete_vpc(VpcId=vpc_id)


def create_dynamodb_table(
    name, attr_name, attr_type, key_type, region_name
):
    """Creates a DynamoDB table."""
    client = boto3.client("dynamodb", region_name=region_name)
    resp = client.create_table(
        TableName=name,
        AttributeDefinitions=[
            {
                "AttributeName": attr_name,
                "AttributeType": attr_type
            }
        ],
        KeySchema=[{"AttributeName": attr_name, "KeyType": key_type}],
    )
    return resp["TableDescription"]["TableName"]


def create_subnet(cidr_block, vpc_id, region_name):
    """Creates a VPC subnet."""
    client = boto3.client("ec2", region_name=region_name)
    resp = client.create_subnet(VpcId=vpc_id, CidrBlock=cidr_block,)
    return resp["Subnet"]["SubnetId"]


def create_volume(size, availability_zone, region_name):
    """Creates an EC2 volume."""
    client = boto3.client("ec2", region_name=region_name)
    resp = client.create_volume(Size=size, AvailabilityZone=availability_zone)
    volume_id = resp["VolumeId"]
    create_time = resp["CreateTime"]
    account_id = get_account_id()
    return (
        f"arn:aws:ec2:{region_name}:{account_id}:volume/{volume_id}",
        create_time,
    )


def get_account_id():
    """Gets the account ID associated with the current session."""
    sts_client = boto3.client("sts")
    return sts_client.get_caller_identity()["Account"]


def create_vpc(cidr_block, region_name):
    """Creates a VPC."""
    client = boto3.client("ec2", region_name=region_name)
    resp = client.create_vpc(CidrBlock=cidr_block)
    return resp["Vpc"]["VpcId"]


def create_flow_log(vpc_id, dest_bucket_arn, region_name):
    """Creates a VPC flow log."""
    client = boto3.client("ec2", region_name=region_name)
    resp = client.create_flow_logs(
        ResourceIds=[vpc_id],
        ResourceType="VPC",
        TrafficType="ALL",
        LogDestinationType="s3",
        LogDestination=dest_bucket_arn,
        MaxAggregationInterval=600,
    )
    flow_log_ids = resp["FlowLogIds"]
    assert len(flow_log_ids) == 1
    flow_log_id = flow_log_ids[0]
    flow_logs_resp = client.describe_flow_logs(FlowLogIds=[flow_log_id])
    creation_time = flow_logs_resp["FlowLogs"][0]["CreationTime"]
    return flow_log_id, creation_time


def create_iam_policy(name, policy_doc):
    """Creates an IAM policy."""
    client = boto3.client("iam")
    resp = client.create_policy(
        PolicyName=name,
        PolicyDocument=json.dumps(policy_doc),
    )
    return resp["Policy"]["Arn"], resp["Policy"]["PolicyId"]


def create_iam_role(
    name, assume_role_policy_doc, description, max_session_duration
):
    """Creates an IAM role."""
    client = boto3.client("iam")
    resp = client.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(assume_role_policy_doc),
        Description=description,
        MaxSessionDuration=max_session_duration,
    )
    return resp["Role"]["Arn"]


def create_lambda_function(
    name,
    runtime,
    role_name,
    handler,
    description,
    timeout,
    memory_size,
    publish,
    region_name,
):
    """Creates a Lambda function."""
    # pylint: disable=too-many-arguments

    zip_content = None
    zip_output = io.BytesIO()
    with zipfile.ZipFile(zip_output, "w", zipfile.ZIP_DEFLATED) as zip_file:
        func_str = """
def lambda_handler(event, context):
    print("fake lambda handler")
    return event
"""
        zip_file.writestr("lambda_function.py", func_str)
        zip_file.close()
        zip_output.seek(0)
        zip_content = zip_output.read()

    client = boto3.client("lambda", region_name=region_name)
    resp = client.create_function(
        FunctionName=name,
        Runtime=runtime,
        Role=role_name,
        Handler=handler,
        Code={"ZipFile": zip_content},
        Description=description,
        Timeout=timeout,
        MemorySize=memory_size,
        Publish=publish,
    )
    return resp["FunctionArn"]


def create_bucket(name, account_id, region_name):
    """Creates a S3 bucket."""
    client = boto3.client("s3")
    client.create_bucket(Bucket=name)
    buckets = client.list_buckets()["Buckets"]
    creation_date = None
    for bucket in buckets:
        if bucket["Name"] == name:
            creation_date = bucket["CreationDate"]
    if not creation_date:
        raise Exception("BUG: error determining test bucket creation date")
    return (
        f"arn:aws:s3:{region_name}:{account_id}:bucket/{name}",
        creation_date,
    )
