# Security Graph - Altimeter Universe

## Security Graph

Security Graph is a data architecture that provides real-time views of assets
and their relationships. Assets to be considered include software, cloud
resources and, in general, any piece of information that a security team needs
to protect.

Security Graph not only stores the catalog of active assets and the assets
assigned to teams. It also keeps a historical log of the multidimensional
relationships among these assets, including their attributes relevant to
security.

## Altimeter Universe

The Altimeter universe takes the AWS accounts stored in the [Security Graph -
Asset Inventory] and uses Tableau [Altimeter] to gather information about the
AWS assets in these accounts.

## Test suite

### Update testdata

The golden files located at `/tests/testdata` can be updated with:

```
./script/test --write-testdata
```

It is also possible to update a specific golden file by specifying the name of
the corresponding test case. For instance, in the case of
`/tests/testdata/graph.json`:

```
./script/test --write-testdata tests/test_scan.py::test_run
```

## Python dependencies

Both direct and transitive dependencies must be pinned. In order to do that we
use [pip-compile]. After modifying the file `requirements.in`, you must run the
following command to update `requirements.txt`:

```
script/pip-compile requirements/requirements.in
```

## Contributing

**This project is in an early stage, we are not accepting external
contributions yet.**

To contribute, please read the contribution guidelines in [CONTRIBUTING.md].


[Altimeter]: https://github.com/tableau/altimeter
[Security Graph - Asset Inventory]: https://github.com/adevinta/graph-asset-inventory-api
[pip-compile]: https://pypi.org/project/pip-tools/
[CONTRIBUTING.md]: CONTRIBUTING.md
