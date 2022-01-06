# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Kibana cli commands."""
import uuid

import glob
import os
import re
from functools import reduce
import click

import kql
from kibana import Signal, RuleResource
from .cli_utils import multi_collection
from .main import root
from .misc import add_params, client_error, kibana_options, get_kibana_client
from .customer_loader import load_customer_files
from .schemas import downgrade
from .utils import format_command_options


@root.group('kibana')
@add_params(*kibana_options)
@click.pass_context
def kibana_group(ctx: click.Context, **kibana_kwargs):
    """Commands for integrating with Kibana."""
    ctx.ensure_object(dict)

    # only initialize an kibana client if the subcommand is invoked without help (hacky)
    if click.get_os_args()[-1] in ctx.help_option_names:
        click.echo('Kibana client:')
        click.echo(format_command_options(ctx))

    else:
        ctx.obj['kibana'] = get_kibana_client(**kibana_kwargs)


@kibana_group.command("upload-rule")
@multi_collection
@click.option('--replace-id', '-r', is_flag=True, help='Replace rule IDs with new IDs before export')
@click.option("--dry-run", '-d', is_flag=True, help='Test configurations')
@click.pass_context
def upload_rule(ctx, rules, replace_id, dry_run, decorator=None):
    """Upload a list of rule .toml files to Kibana."""
    kibana = ctx.obj['kibana']
    api_payloads = []

    for rule in rules:
        try:
            payload = rule.contents.to_api_format()
            payload.setdefault("meta", {"original": {"id": rule.id}}).update(rule.contents.metadata.to_dict())

            if replace_id:
                payload["rule_id"] = str(uuid.uuid4())

            payload = downgrade(payload, target_version=kibana.version)

        except ValueError as e:
            client_error(f'{e} in version:{kibana.version}, for rule: {rule.name}', e, ctx=ctx)

        rule = RuleResource(payload)

        if decorator:
            rule = decorator(rule)

        if rule:
            api_payloads.append(rule)

    if dry_run:
        click.echo(f"Generated {len(api_payloads)} rule payloads")
        click.echo(api_payloads)
        return

    with kibana:
        results = RuleResource.bulk_create(api_payloads)

    success = []
    errors = []
    for result in results:
        if 'error' in result:
            errors.append(f'{result["rule_id"]} - {result["error"]["message"]}')
        else:
            success.append(result['rule_id'])

    if success:
        click.echo('Successful uploads:\n  - ' + '\n  - '.join(success))
    if errors:
        click.echo('Failed uploads:\n  - ' + '\n  - '.join(errors))

    return results


@kibana_group.command("upload-customer")
@click.argument("toml-files", nargs=-1, required=True)
@click.option("--dry-run", '-d', is_flag=True, help='Test configurations')
@click.pass_context
def upload_customer(ctx, dry_run, toml_files):
    """Upload a list of customer .toml files to Kibana."""
    customer_files = load_customer_files(paths=toml_files)
    for customer_file in customer_files.values():
        customer = customer_file['customer']
        click.echo(f"Loading rules for {customer['name']} {customer['rules']}")

        rule_files = reduce(list.__add__,
                            map((lambda r: sorted(glob.glob(os.path.join('rules/', r)))),
                                customer['rules']))

        existing_rules = []
        active_customer_rule_ids = []
        kibana = ctx.obj['kibana']
        with kibana:
            for existing_rule in RuleResource.find(filter='alert.attributes.tags:' + customer['name']
                                                          + ' AND alert.attributes.enabled:true'):
                existing_rules.append(existing_rule)

        click.echo(f"There are {len(existing_rules)} existing rules for customer {customer['name']}")

        def decorator(rule):
            # print(rule)
            customer_rule_id = customer['id'] + '_' + rule['meta']['original']['id']
            active_customer_rule_ids.append(customer_rule_id)
            rule_log_id = f"[{customer_rule_id}] \"{rule['name']}\""
            if 'tags' not in rule:
                rule['tags'] = []

            rule['tags'].append(customer['name'])
            rule['tags'].append(customer_rule_id)
            rule['tags'].append(f"original_version_{rule['version']}")

            # Modify index
            if 'index' in rule:
                rule['index'] = list(map(lambda idx: customer['id'] + '_' + idx, rule['index']))

            # Load current rules, capture configured exceptions and timeline templates.
            try:
                current_rule = next(r for r in existing_rules if customer_rule_id in r['tags'])

                # If the version is different, then disable old one.
                # Rule versions are defined at version.lock.json.
                click.echo(f"Found the existing rule {rule_log_id}")
                click.echo(current_rule)
                click.echo(f"Current exceptions_list {current_rule['exceptions_list']}")

                # The version of rule can be incremented when it gets updated by the user from Kibana UI.
                # The original version is recorded as a tag.
                # Cannot rely on 'meta' tag as it gets overwritten when the user updated the rule.
                current_rule_version = get_original_version(current_rule['tags'])
                if rule['version'] > current_rule_version:
                    click.echo(f"Upgrading rule {rule_log_id} from {current_rule_version} to {rule['version']}")
                    current_rule['enabled'] = False
                    current_rule.put()

                    # copy exception
                    if 'exceptions_list' in current_rule:
                        rule['exceptions_list'] = current_rule['exceptions_list']

                    # copy timeline template
                    if 'timeline_id' in current_rule:
                        rule['timeline_id'] = current_rule['timeline_id']

                    if 'timeline_title' in current_rule:
                        rule['timeline_title'] = current_rule['timeline_title']

                else:
                    click.echo(f"Rule {rule_log_id} ver {current_rule_version} already exists. Do nothing.")
                    return None

            except StopIteration:
                click.echo(f"Rule {rule_log_id} does not exist yet. Creating it.")
                pass

            return rule

        if len(rule_files) == 0:
            click.echo(f"No rules defined for {customer['name']}")
        else:
            # Replace id is required, because the same id cannot be used among multiple customers.
            # Also, the id format is validated at the GET /api/detection_engine/rules?id=XXX.
            # The id must be in the form of uuid4.
            ctx.invoke(upload_rule, rule_file=rule_files, replace_id=True, dry_run=dry_run, decorator=decorator)

        inactive_rules = [ext_rule for ext_rule in existing_rules
                          if not any(cus_rid in ext_rule['tags'] for cus_rid in active_customer_rule_ids)]

        # Disable rules that no longer exists in the customer toml file.
        if len(inactive_rules) > 0:
            click.echo(f"Deactivating {len(inactive_rules)} existing rules...")
            with kibana:
                for inactive_rule in inactive_rules:
                    click.echo(f"{inactive_rule['name']}: {inactive_rule['tags']}")
                    if not dry_run:
                        inactive_rule['enabled'] = False
                        inactive_rule.put()

        if dry_run:
            click.echo(f"Checked rules for {customer['name']}")
        else:
            click.echo(f"Successfully uploaded rules for {customer['name']}")


def get_original_version(tags):
    for tag in tags:
        m = re.search(r"^original_version_(\d+)$", tag)
        if m:
            return int(m.group(1))
    return None


@kibana_group.command('search-alerts')
@click.argument('query', required=False)
@click.option('--date-range', '-d', type=(str, str), default=('now-7d', 'now'), help='Date range to scope search')
@click.option('--columns', '-c', multiple=True, help='Columns to display in table')
@click.option('--extend', '-e', is_flag=True, help='If columns are specified, extend the original columns')
@click.pass_context
def search_alerts(ctx, query, date_range, columns, extend):
    """Search detection engine alerts with KQL."""
    from eql.table import Table
    from .eswrap import MATCH_ALL, add_range_to_dsl

    kibana = ctx.obj['kibana']
    start_time, end_time = date_range
    kql_query = kql.to_dsl(query) if query else MATCH_ALL
    add_range_to_dsl(kql_query['bool'].setdefault('filter', []), start_time, end_time)

    with kibana:
        alerts = [a['_source'] for a in Signal.search({'query': kql_query})['hits']['hits']]

    table_columns = ['host.hostname', 'signal.rule.name', 'signal.status', 'signal.original_time']
    if columns:
        columns = list(columns)
        table_columns = table_columns + columns if extend else columns
    click.echo(Table.from_list(table_columns, alerts))
    return alerts
