import pytest

from airiam.main import parse_args
from airiam.Reporter import OutputFormat


class TestAiriam:
    def test_arg_parser_find_unused_default(self):
        args = parse_args(['find_unused'])
        assert args.command == 'find_unused'
        assert args.last_used_threshold == 90
        assert args.profile is None
        assert args.no_cache is False
        assert args.output == OutputFormat.cli

    def test_arg_parser_find_unused_custom(self):
        args = parse_args(['find_unused', '-p', 'dev', '-l', '30', '--no-cache'])
        assert args.command == 'find_unused'
        assert args.last_used_threshold == 30
        assert args.profile == 'dev'
        assert args.no_cache is True

    def test_arg_parser_recommend_groups_default(self):
        args = parse_args(['recommend_groups'])
        assert args.command == 'recommend_groups'
        assert args.last_used_threshold == 90
        assert args.profile is None
        assert args.no_cache is False
        assert args.output == OutputFormat.cli

    def test_arg_parser_recommend_groups_custom(self):
        args = parse_args(['recommend_groups', '-p', 'dev', '-l', '30', '--no-cache'])
        assert args.command == 'recommend_groups'
        assert args.last_used_threshold == 30
        assert args.profile == 'dev'
        assert args.no_cache is True

    def test_arg_parser_terraform_default(self):
        args = parse_args(['terraform'])
        assert args.command == 'terraform'
        assert args.last_used_threshold == 90
        assert args.without_unused is False
        assert args.profile is None
        assert args.directory == 'results'
        assert args.no_cache is False
        assert args.without_groups is False
        assert args.without_import is False

    def test_arg_parser_terraform_custom(self):
        args = parse_args(['terraform', '-p', 'dev', '--without-unused', '-l', '30', '--no-cache', '-d', 'tf_res', '--without-groups',
                           '--without-import'])
        assert args.command == 'terraform'
        assert args.last_used_threshold == 30
        assert args.without_unused is True
        assert args.profile == 'dev'
        assert args.directory == 'tf_res'
        assert args.no_cache is True
        assert args.without_groups is True
        assert args.without_import is True
