from redcrucible.pipeline import stage_registry

from .dnlib_patcher import DnlibPatcherStage
from .donut import DonutStage
from .obfuscar import ObfuscarStage
from .polymorphic_loader import PolymorphicLoaderStage

stage_registry.register(ObfuscarStage())
stage_registry.register(DnlibPatcherStage())
stage_registry.register(DonutStage())
stage_registry.register(PolymorphicLoaderStage())
