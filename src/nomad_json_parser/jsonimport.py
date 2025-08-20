from typing import (
    TYPE_CHECKING,
)

if TYPE_CHECKING:
    pass


import importlib
import json

from nomad.config import config
from nomad.datamodel.data import (
    ArchiveSection,
    EntryData,
)
from nomad.metainfo import (
    Quantity,
    Reference,
    SchemaPackage,
    SubSection,
)
from structlog.stdlib import (
    BoundLogger,
)

configuration = config.get_plugin_entry_point('nomad_json_parser:jsonmapper_entry')
m_package = SchemaPackage()


def get_class(class_string, logger):
    try:
        class_obj = getattr(
            importlib.import_module('.'.join(class_string.split('.')[:-1])),
            class_string.split('.')[-1],
        )
        return class_obj
    except AttributeError:
        logger.warning(
            'The module '
            + '.'.join(class_string.split('.')[:-1])
            + ' has no class '
            + class_string.split('.')[-1]
            + '.'
        )
    except ModuleNotFoundError:
        logger.warning(
            'The module ' + '.'.join(class_string.split('.')[:-1]) + ' was not found.'
        )
    return


def createrulesjson(rulesclasses):
    rulesdict = dict()
    for rule in rulesclasses:
        thisrule = dict()
        thisrule.update({'source': rule['source'], 'target': rule['target']})
        if 'default_value' in rule.keys():
            thisrule.update({'default_value': rule['default_value']})
        if 'use_rule' in rule.keys():
            thisrule.update({'use_rule': rule['use_rule']})
        if 'conditions' in rule.keys():
            condlist = []
            for cond in rule['conditions']:
                condlist.append(
                    {
                        cond['name']: {
                            'regex_path': cond['regex_path'],
                            'regex_pattern': cond['regex_pattern'],
                        }
                    }
                )
            thisrule.update({'conditions': condlist})
        rulesdict.update(dict({rule['name']: thisrule}))
    return json.dumps({'rules': rulesdict})


class RuleCondition(ArchiveSection):
    name = Quantity(type=str)
    regex_path = Quantity(type=str, description='Path to data field')
    regex_pattern = Quantity(type=str, description='Regex condition for data field')


class MapperRule(ArchiveSection):
    name = Quantity(type=str)
    source = Quantity(type=str, description='Source of the rule')
    target = Quantity(type=str, description='Target of the rule')
    default_value = Quantity(type=str, description='Default value of the rule')
    use_rule = Quantity(type=str, description='use rule field of the rule')
    conditions = SubSection(section_def=RuleCondition, repeats=True)


class MainMapper(ArchiveSection):
    name = Quantity(type=str)
    path_to_schema = Quantity(
        type=str, description='Path to the schema for the section'
    )
    rules = SubSection(section_def=MapperRule, repeats=True)

    def normalize(self, archive, logger: BoundLogger) -> None:
        super().normalize(archive, logger)


class SubSectionMapper(MainMapper):
    main_key = Quantity(
        type=str, description='Key of the main class, where the SubSectin is linked.'
    )
    is_archive = Quantity(
        type=bool,
        description='Archives will be created separately and linked only as reference',
    )
    repeats = Quantity(
        type=bool,
        description='Marks a repeatable Subsection, attaches to existing list.',
    )

    def normalize(self, archive, logger: BoundLogger) -> None:
        super().normalize(archive, logger)


class JsonMapper(EntryData, ArchiveSection):
    mapper_key = Quantity(type=str, description='Key to match with the imported JSON')
    main_mapping = SubSection(section_def=MainMapper)
    subsection_mappings = SubSection(section_def=SubSectionMapper, repeats=True)
    mapper_file = Quantity(type=str, description='Path to mapper file')

    def normalize(self, archive, logger: BoundLogger) -> None:
        super().normalize(archive, logger)


class MappedJson(EntryData, ArchiveSection):
    json_file = Quantity(type=str, escription='Link to json file')
    mapper_key = Quantity(type=str, description='Key to map with the mapper schema')
    # mapper_reference = Quantity(
    #     type=JsonMapper, description='A reference to the JsonMapper entry.'
    # )

    mapper_reference = Quantity(
        type=Reference(JsonMapper.m_def),
        description='A reference to the component system.',
    )

    def normalize(self, archive, logger: BoundLogger) -> None:
        super().normalize(archive, logger)


m_package.__init_metainfo__()
