import dataclasses
from . import equality

@dataclasses.dataclass
class JavaClass(equality.CommonEqualityMixin):
    """A class information."""

    package_name: str
    class_name: str

    def __init__(self, package_name:str, class_name:str):
        self.package_name = package_name
        self.class_name = class_name
