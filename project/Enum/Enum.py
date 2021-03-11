from enum import Enum


class RelationType(Enum):
    HOSTS = "hosts"
    USES = "uses"
    PROVIDES = "provides"
    CONNECTS = "connects"
