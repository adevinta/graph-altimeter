# IAM Policies expansion

This module receives the dictionary graph generated by [Altimeter] and expands
it to add an edge from each policy, embedded or not, to the vertices
representing the AWS resources the policies would potentially grant access to.
It has the following limitations:

* It does not ake into account the statements that "Deny" access to the resources,
by now it only takes into account "Allow" statements.

* Even though the edges it generates contain information about the type of
access, `Read-Write` or only `Read`, that information is not actually persisted
as the logic to persist custom properties in edges is not implemented yet by
the Neptune client.

* The conditions defined in the policies are not taken into account.

* The assume role policies are not taken into account.

## Determining the name of the AWS resources affected by an action

The file: `iam_definition.json` contains the information about all the possible
actions in a policy document and the names of the affected resources for a
given AWS service.
For instance, the action `DeleteTable` for the AWS Service: `dynamodb`
affect to the resource `table`

The file is genrerated by a [tool] from the awesome [Parliament] utility.

### Updating the iam_definitions.json file

Execute the following commands:

```bash
git clone https://github.com/duo-labs/parliament
cd parliament
git checkout 1.5.2
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements
python3 utils/update_iam_data.py > iam_definition.json
```

[Altimeter]: https://github.com/tableau/altimeter/blob/3bb875dff4a54aaf8df3c5dc38295a632259922f/altimeter/core/graph/graph_set.py#L125
[Parliament]: https://github.com/duo-labs/parliament
[tool]: https://github.com/duo-labs/parliament/blob/main/utils/update_iam_data.py
