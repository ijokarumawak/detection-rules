# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

"""Load rule metadata transform between rule and api formats."""
import glob
import io
import os
import pytoml

from .utils import get_path, cached


CUSTOMERS_DIR = get_path("customers")


def reset():
    """Clear all rule caches."""
    load_customer_files.clear()


@cached
def load_customer_files(verbose=True, paths=None):
    """Load the customer toml files."""
    file_lookup = {}  # type: dict[str, dict]

    if verbose:
        print("Loading customers from {}".format(CUSTOMERS_DIR))

    if paths is None:
        paths = sorted(glob.glob(os.path.join(CUSTOMERS_DIR, '**', '*.toml'), recursive=False))

    for customer_file in paths:
        try:
            # use pytoml instead of toml because of annoying bugs
            # https://github.com/uiri/toml/issues/152
            # might also be worth looking at https://github.com/sdispater/tomlkit
            with io.open(customer_file, "r", encoding="utf-8") as f:
                file_lookup[customer_file] = pytoml.load(f)
        except Exception:
            print(u"Error loading {}".format(customer_file))
            raise

    if verbose:
        print("Loaded {} customers".format(len(file_lookup)))
    return file_lookup
