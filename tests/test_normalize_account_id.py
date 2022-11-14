"""Tests for AWS account ID normalization."""
import pytest
from graph_altimeter.scan import normalize_aws_account, InvalidAWSAccount


def test_normalize_aws_account_from_valid_arn():
    """Tests that the normalize_aws_account function properly extracts the
    account id from an arn."""
    account_id = "123456789111"
    account_arn = f'arn:aws:iam::{account_id}:root'
    # Test it extracts
    got_account_id = normalize_aws_account(account_arn)
    assert got_account_id == account_id


def test_normalize_aws_account_from_already_account_id():
    """Tests that the normalize_aws_account function returns the account_id
    passed in."""
    account_id = "123456789111"
    # Test it extracts
    got_account_id = normalize_aws_account(account_id)
    assert got_account_id == account_id


def test_normalize_aws_account_from_invalid_arn():
    """Tests that the normalize_aws_account function returns an exception
    for an invalid account arn."""
    account_arn = "arn:aws:iam::111:root"
    with pytest.raises(InvalidAWSAccount):
        normalize_aws_account(account_arn)


def test_normalize_aws_account_from_invalid_account_id():
    """Tests that the normalize_aws_account function returns an exception
    for an invalid account id."""
    account_id = "111"
    with pytest.raises(InvalidAWSAccount):
        normalize_aws_account(account_id)
