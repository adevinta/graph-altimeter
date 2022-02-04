"""This modules provides the classes, functions and errors used to feed and
query the Altimeter Universe."""

from graph_altimeter.universe import Universe, UniverseVersion


CURRENT_UNIVERSE_VERSION = "0.0.1"
"""Current Altimeter Universe version."""

CURRENT_UNIVERSE = Universe(UniverseVersion(CURRENT_UNIVERSE_VERSION))
"""Instace of the current Altimeter Universe."""


class AltimeterError(Exception):
    """Represents a generic Altimeter error."""


class EnvVarNotSetError(AltimeterError):
    """It is returned when an environment variable was not set."""

    def __init__(self, name=None):
        msg = 'environment variable not set'
        if name is not None:
            msg = f'environment variable not set: {name}'

        super().__init__(msg)

        self.name = name


class InvalidRoleArnError(Exception):
    """It is returned when an arn is invalid."""

    def __init__(self, arn=None):
        msg = 'invalid role arn'
        if arn is not None:
            msg = f'invalid role arn: {arn}'

        super().__init__(msg)

        self.arn = arn