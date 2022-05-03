"""This defines the logic that expands the IAM policies of a graph produced by
Atimeter."""

import json
import os
import re
import uuid
import logging

from policyuniverse.policy import Policy
from policyuniverse.arn import ARN

from graph_altimeter import (
    InvalidArnError,
    InvalidArnPatternError,
    EmptyActionsError,
)

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


iam_definitions_path = os.path.join(
    os.path.dirname(os.path.realpath(__file__)),
    "iam_definition.json"
)


def _load_iam_data(path):
    """Builds a dictionary containing the information about all the
    AWS IAM resources and the actions they relate to (for more information look
    at the README.md in this directory). The keys of the dictionary are all the
    possible IAM policy actions and the values are sets containing the
    resources they allow access to. For instance:
    {'ec2:allocateaddres':{'elastic-ip', 'ipv4pool-ec2'}}"""
    data = None
    with open(path, "r") as file:
        data = json.load(file)
    actions = {}
    for service in data:
        prefix = service["prefix"]
        for privilege in service["privileges"]:
            action = privilege["privilege"].lower()
            action = f"{prefix}:{action}"
            resources = set()
            for resource_type in privilege["resource_types"]:
                if "resource_type" not in resource_type:
                    continue
                resource = resource_type["resource_type"].replace("*", "")
                if resource == "":
                    continue
                # The actions related to S3 can give access to objects, buckets
                # or both (an object is a file in a bucket). Altimeter scans
                # buckets, but not objects. So,for us, if an action give access
                # to a object, it gives access to whole the bucket.
                if prefix == "s3" and resource == "object":
                    resource = "bucket"
                resources.add(resource)
            actions[action] = resources
    return actions


# Holds the data about the AWS IAM policy actions and the resources they give
# access to.
actions_info = _load_iam_data(iam_definitions_path)


def resources_for_action(action):
    """Returns for a given action, e.g.: ``dynamodb:getitem``, a set
    with the resource names that it grants access to, for instance:
    ``{"table"}``."""
    if action in actions_info:
        resources = actions_info[action]
        return resources
    return set()


def expand_iam_policies(graph_dict):
    """Expand the vertices labeled ``embedded_policy`` or ``aws:iam:policy``
    by creating edges between them and the vertices representing the
    aws-resources they give access to."""
    edges = graph_dict["edges"]
    vertices = graph_dict["vertices"]
    for v in vertices:
        rules = []
        policy_document = None
        policy_account = None
        v_id = v["~id"]

        if v["~label"] == "embedded_policy":
            if "policy_document" in v:
                policy_document = v["policy_document"]
                policy_account = v["account_id"]
        elif v["~label"] == "aws:iam:policy":
            if "default_version_policy_document_text" in v:
                policy_document = v["default_version_policy_document_text"]
                policy_account = v["account_id"]

        if policy_document is not None:
            rules = _aws_arn_rules(policy_document, policy_account)
        iam_edges = _link_to_resources(v_id, rules, vertices)
        for edge in iam_edges:
            edges.append(edge)

    graph_dict["edges"] = edges


def _link_to_resources(from_id, rules, vertices):
    """Returns a set of edges connecting the vertex with the id ``from_id`` to
    the any vertex in the given ``vertices`` that match against any of
    specified set of ``rules``."""
    edges = []
    if rules is None:
        return []
    for v in vertices:
        if "arn" not in v:
            continue
        arn = v["arn"]
        for rule in rules:
            # TODO: We don't follow rules of type different than ``allow`` by
            # now as it could potentially make explode the number of Edges to
            # create, we should review this.
            if rule.effect != "Allow":
                continue
            permissions = rule.matches(arn)
            if permissions is None:
                continue
            edge = _create_edge(
                    from_id,
                    v["~id"],
                    "iam_resource_link",
                    {"permission": permissions}
                )
            edges.append(edge)
    return edges


def _create_edge(from_id, to_id, label, properties):
    """Creates and returns and Edge between the specified vertex ids, with
    the given labels and properties."""

    # TODO: By now the neptune_client does write arbitrary properties in edges
    # so the properties specified here are not actually persisted.
    e = {
        "~id": uuid.uuid1(),
        "~from": from_id,
        "~to": to_id,
        "~label": label,
    }
    for name, value in properties.items():
        e[name] = value
    return e


def _aws_arn_rules(document, account_id):
    """Given a string containing a policy document, and the account the policy
    belongs to, returns the corresponding list of rules."""
    document = json.loads(document)
    policy = Policy(document)
    rules = []
    for statement in policy.statements:
        for resource in statement.resources:
            try:
                rule = ARNRule(
                        statement.action_summary(),
                        statement.actions_expanded,
                        resource,
                        statement.effect,
                        account_id,
                )
                rules.append(rule)
            except InvalidArnPatternError as e:
                # There could be policy documents that contain invalid
                # policies.
                logger.warning(e)
            except EmptyActionsError:
                # The statement does not contain any action.
                # TODO: take into account the "NotAction" field.
                logger.warning('statement with no actions')
    return rules


class ARNRule:
    """Represent a rule parsed from a policy document statement."""
    PERMISSIONS_TRANSLATION = {
            "Tagging": "Write",
            "Permissions": "Write",
            "Read": "Read",
            "List": "Read",
            "Write": "Write",
    }

    def __init__(
        self,
        service_permissions,
        actions,
        arn_pattern,
        effect,
        account
    ):  # pylint: disable=too-many-arguments
        """Creates a rule from a given set of service permissions, actions, an
        arn pattern, an effect and an account. """
        # Service permissions example:
        # {
        #   'sqs': {'Tagging', 'Permissions', 'Read', 'List', 'Write'},
        #   'ssm': {'Write'}
        # }
        # Actions example:
        # {
        #     'sqs:tagqueue',
        #     'dynamodb:getitem'
        # }
        # arn pattern example:
        # arn:aws:ssm:eu-west-1:*:parameter/grafana/loki/*

        if len(service_permissions) == 0 or len(actions) == 0:
            raise EmptyActionsError

        # Translate the permissions to Read and Write.
        translated = {}
        for tech in service_permissions:
            permissions = {
                ARNRule.PERMISSIONS_TRANSLATION[permission] for
                permission in service_permissions[tech]
                if permission is not None
            }
            translated[tech] = permissions
            pattern = ARN(arn_pattern)

        # We don't parse patterns that are invalid, except for the case of the
        # pattern "*" that the policyuniverse lib considers invalid but it's
        # indeed valid.
        if pattern.error and pattern.arn != "*":
            raise InvalidArnPatternError(arn_pattern)

        self.arn_pattern = pattern
        self.service_permissions = translated
        self.effect = effect
        self.actions = actions
        self.account = account

    def __str__(self):
        arn_pattern = f"{self.arn_pattern.arn}"
        return f"""account:{str(self.account)}
        arn_pattern:{str(arn_pattern)}
        actions:{str(self.actions)}
        service_permissions:{str(self.service_permissions)}
        effect:{str(self.effect)}
        """

    # pylint: disable=too-many-return-statements, too-many-branches
    def matches(self, arn):
        """Returns a set with the permissions a rule grants to an
        aws resource given its arn. Returns None if no permissions
        are granted. The possible permissions are 'Read' and 'Write'."""
        target_arn = ARN(arn)
        if target_arn.error:
            raise InvalidArnError(arn)

        # By now, we are not following trust relationships across accounts, so
        # a rule defined in one account only matches resources of the same
        # account.
        if target_arn.account_number != self.account:
            return None

        if self.arn_pattern.arn == "*":
            if target_arn.tech in self.service_permissions:
                if self._matches_resource_name(target_arn.name):
                    return self.service_permissions[target_arn.tech]
            return None

        if not _arn_part_matches(
            self.arn_pattern.partition,
            target_arn.partition
        ):
            return None

        if not _arn_part_matches(
            self.arn_pattern.tech,
            target_arn.tech
        ):
            return None

        if not _arn_part_matches(
            self.arn_pattern.region,
            target_arn.region
        ):
            return None

        if not _arn_part_matches(
            self.arn_pattern.account_number,
            target_arn.account_number
        ):
            return None

        name_pattern = self.arn_pattern.name
        translated_target_name = _translate_target_name(target_arn)

        if "*" in name_pattern:
            if not self._matches_wildcard_resource_name(
                translated_target_name
            ):
                return None

            if target_arn.tech in self.service_permissions:
                return self.service_permissions[target_arn.tech]

            return None

        if translated_target_name != name_pattern:
            return None

        if target_arn.tech in self.service_permissions:
            if self._matches_resource_name(target_arn.name):
                return self.service_permissions[target_arn.tech]
        return None

    def _matches_wildcard_resource_name(self, target_name):
        """Tests if the rule containing a wildcard in the name pattern matches
        a given arn name part."""
        name_pattern = self.arn_pattern.name.replace("*", ".*")
        # We must ensure that a ``name_pattern`` like this: "name/*" matches a
        # ``target_name`` like this "name".
        if name_pattern.endswith("/.*") and not target_name.endswith("/"):
            target_name = target_name + "/"
        match = re.match(name_pattern, target_name) is not None
        return match

    def _matches_resource_name(self, target_name: str):
        """Tests if a given target name with the format 'resource_name/path'
        matches the name pattern of the rule."""
        # Target name has the format "resource_name/path".
        resource_name = target_name.split("/")[0]
        valid_resources = set()
        for action in self.actions:
            resources = resources_for_action(action)
            for resource in resources:
                valid_resources.add(resource)
        return resource_name in valid_resources


def _translate_target_name(target_arn):
    """In Altimeter all the arn's have at the beggining of the name part
    of the arn the name of the service. This is not the case for all the
    'real' arn's. By now this only affects us in the case of s3 buckets."""
    if target_arn.tech == "s3":
        return target_arn.name.removeprefix("bucket/")
    return target_arn.name


def _arn_part_matches(arn_pattern_part, arn_target_path):
    if arn_pattern_part in ["*", ""]:
        return True
    return arn_pattern_part == arn_target_path
