from dataclasses import dataclass


@dataclass(frozen=True)
class RepositoryInfo:
    """Describes the source code repository associated with a scanned SBOM.

    :param cloneUrl: The URL used to clone the repository. Must not be ``None``.
    :type cloneUrl: str
    :param branch: The name of the branch that was scanned, if known.
    :type branch: str | None
    :param commit: The commit hash of the scanned code, if known.
    :type commit: str | None
    :raises ValueError: If ``cloneUrl`` is ``None``.
    """

    cloneUrl: str
    branch: str | None = None
    commit: str | None = None

    def __post_init__(self):
        if self.cloneUrl is None:
            raise ValueError("cloneUrl must not be None")
