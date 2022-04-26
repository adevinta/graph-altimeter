"""Tests for the ``universe`` module."""

import tempfile
import json

from altimeter.aws.resource.awslambda.function import (
    LambdaFunctionResourceSpec
)
from altimeter.aws.resource.ec2.flow_log import FlowLogResourceSpec
from altimeter.aws.resource.ec2.volume import EBSVolumeResourceSpec
from altimeter.aws.resource.ec2.subnet import SubnetResourceSpec
from altimeter.aws.resource.ec2.vpc import VPCResourceSpec
from altimeter.aws.resource.iam.policy import IAMPolicyResourceSpec
from altimeter.aws.resource.iam.role import IAMRoleResourceSpec
from altimeter.aws.resource.s3.bucket import S3BucketResourceSpec
from altimeter.core.config import AWSConfig
from helpers import (
    create_graph,
    compare_graphs,
)

from conftest import TESTDATA_DIR
from graph_altimeter.scan.config import AltimeterConfig
from graph_altimeter.scan import run


def test_run(g, opt_write_golden_file, aws_resources):
    """Tests running an Altimeter Scan."""
    # pylint: disable=too-many-locals

    account_id = aws_resources["account"]
    target_account_role = aws_resources["target_account_role"]
    expected_graph = aws_resources["graph"]

    with tempfile.TemporaryDirectory() as temp_dir:
        config_dict = {
            'artifact_path': temp_dir,
            'graph_name': "alti",
            'pruner_max_age_min': 0,
            'concurrency': {
                'max_account_scan_threads': 1,
                'max_svc_scan_threads': 1,
            },
            'scan': {
                'scan_sub_accounts': False,
                'regions': [],
                'accounts': [],
                'preferred_account_scan_regions': [
                   "eu-central-1",
                   "eu-north-1",
                   "eu-west-1",
                   "eu-west-2",
                   "eu-west-3",
                ]
            },
            'neptune': {
                'use_lpg': "true",
                'host': "gremlin-server",
                'port': 8182,
                'region': "eu-west-1",
                'ssl': False,
                'auth_mode': "default",
            }
        }

        resource_specs = (
                EBSVolumeResourceSpec,
                FlowLogResourceSpec,
                IAMPolicyResourceSpec,
                IAMRoleResourceSpec,
                LambdaFunctionResourceSpec,
                S3BucketResourceSpec,
                SubnetResourceSpec,
                VPCResourceSpec,
        )

        config = AltimeterConfig(config_dict)
        scan_config = config.config_dict([account_id], target_account_role)
        altimeter_config = AWSConfig.parse_obj(scan_config)

        run(altimeter_config, resource_specs=resource_specs)

        vertices = g.V().elementMap().toList()
        edges = g.E().elementMap().toList()
        graph = create_graph(vertices, edges)

        if opt_write_golden_file:
            with open(TESTDATA_DIR / "graph.json", "wb") as graph_file:
                graph_file.write(json.dumps(graph).encode('utf-8'))
        else:
            compare_graphs(graph, expected_graph)
