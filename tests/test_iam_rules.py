"""Tests  for the ARNRules."""

import json

from policyuniverse.policy import Policy

from graph_altimeter.scan.iam import ARNRule


def test_match_rule_global_resource():
    """Tests that the function ``match`` of a rule returns the proper
    permissions when the rule matches a global AWS resource. A global AWS
    resource is a resource that is not tied to an account, so the account ID
    does not appear in its ARN."""
    document = """
    {
        "Statement": [
            {
                "Action": [
                    "s3:GetObject",
                    "s3:PutObject"
                ],
                "Effect": "Allow",
                "Resource": [
                    "arn:aws:s3:::example-bucket"
                ]
            }
        ],
        "Version": "2012-10-17"
        }
    """
    target_arn = "arn:aws:s3:eu-west-1:123456768124:bucket/example-bucket"
    document = json.loads(document)
    policy = Policy(document)
    statement = policy.statements[0]
    resource = statement.resources.pop()
    rule = ARNRule(
        statement.action_summary(),
        statement.actions_expanded,
        resource,
        statement.effect,
        "123456768124"
    )
    assert rule.matches(target_arn) == {"Read", "Write"}


def test_match_resource():
    """Tests that the function ``match`` of a rule returns the proper
    permissions when the rule matches an AWS resource."""
    document = """
        {
            "Statement": [
                {
                    "Action": [
                        "dynamodb:Scan"
                    ],
                    "Effect": "Allow",
                    "Resource": [
                        "arn:aws:dynamodb:*:*:table/table*"
                    ]
                }
            ],
            "Version": "2012-10-17"
        }
    """
    target_arn = "arn:aws:dynamodb:eu-west-1:123456768124:table/table2"
    document = json.loads(document)
    policy = Policy(document)
    statement = policy.statements[0]
    resource = statement.resources.pop()
    rule = ARNRule(
        statement.action_summary(),
        statement.actions_expanded,
        resource,
        statement.effect,
        "123456768124"
    )
    assert rule.matches(target_arn) == {"Read"}


def test_dont_match_different_account_():
    """Tests a rule does not match an AWS resource defined in a different
    account than the rule."""
    document = """
        {
            "Statement": [
                {
                    "Action": [
                        "dynamodb:Scan"
                    ],
                    "Effect": "Allow",
                    "Resource": [
                        "arn:aws:dynamodb:*:*:table/table*"
                    ]
                }
            ],
            "Version": "2012-10-17"
        }
    """
    target_arn = "arn:aws:dynamodb:eu-west-1:111111111111:table/table2"
    document = json.loads(document)
    policy = Policy(document)
    statement = policy.statements[0]
    resource = statement.resources.pop()
    rule = ARNRule(
        statement.action_summary(),
        statement.actions_expanded,
        resource,
        statement.effect,
        "123456768124"
    )
    assert rule.matches(target_arn) is None
