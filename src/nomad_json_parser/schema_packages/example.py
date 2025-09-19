from typing import (
    TYPE_CHECKING,
)

if TYPE_CHECKING:
    pass


from nomad.config import config
from nomad.datamodel.data import (
    ArchiveSection,
    EntryData,
)
from nomad.metainfo import (
    Quantity,
    SchemaPackage,
    SubSection,
)
from structlog.stdlib import (
    BoundLogger,
)

configuration = config.get_plugin_entry_point(
    'nomad_json_parser.schema_packages:example_schema_package'
)
m_package = SchemaPackage()


class SubLevel3(ArchiveSection):
    string = Quantity(type=str, description='String test')

    def normalize(self, archive, logger: BoundLogger) -> None:
        super().normalize(archive, logger)


class SubLevel2(ArchiveSection):
    string = Quantity(type=str, description='String test')
    name = Quantity(type=str, description='String test')
    nesting = SubSection(section_def=SubLevel3)

    def normalize(self, archive, logger: BoundLogger) -> None:
        super().normalize(archive, logger)


class SubLevel1(ArchiveSection):
    string = Quantity(type=str, description='String test')
    nesting = SubSection(section_def=SubLevel2)

    def normalize(self, archive, logger: BoundLogger) -> None:
        super().normalize(archive, logger)


class SubLevelRepeating(ArchiveSection):
    string = Quantity(type=str, description='String test')

    def normalize(self, archive, logger: BoundLogger) -> None:
        super().normalize(archive, logger)


class SubLevelUnit(ArchiveSection):
    unit = Quantity(type=float, description='Number test', unit='m')

    def normalize(self, archive, logger: BoundLogger) -> None:
        super().normalize(archive, logger)


class SubLevelList(ArchiveSection):
    unit = Quantity(type=float, shape=['*'], description='List test', unit='kg')

    def normalize(self, archive, logger: BoundLogger) -> None:
        super().normalize(archive, logger)


class SubLevelReference(EntryData, ArchiveSection):
    name = Quantity(type=str, description='String test')

    def normalize(self, archive, logger: BoundLogger) -> None:
        super().normalize(archive, logger)


class MainLevel(EntryData, ArchiveSection):
    name = Quantity(type=str, description='String test')
    string = Quantity(type=str, description='String test')
    nesting = SubSection(section_def=SubLevel1)
    repeating = SubSection(section_def=SubLevelRepeating, repeats=True)
    unit = SubSection(section_def=SubLevelUnit)
    list = SubSection(section_def=SubLevelList)
    reference = Quantity(
        type=SubLevelReference, description='A reference to the component system.'
    )

    def normalize(self, archive, logger: BoundLogger) -> None:
        super().normalize(archive, logger)


m_package.__init_metainfo__()
