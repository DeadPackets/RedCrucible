from enum import StrEnum


class ArtifactType(StrEnum):
    """Type of artifact flowing through the pipeline."""

    DOTNET_ASSEMBLY = "dotnet_assembly"
    NATIVE_PE = "native_pe"
    DLL = "dll"
    SHELLCODE = "shellcode"
    POWERSHELL = "powershell"


class OutputFormat(StrEnum):
    """Requested output format for the final artifact."""

    EXE = "exe"
    DLL = "dll"
    SHELLCODE = "shellcode"
    POWERSHELL = "ps1"


class Architecture(StrEnum):
    """Target architecture."""

    X86 = "x86"
    X64 = "x64"
    ANY = "any"


class BuildStatus(StrEnum):
    """Status of a build job."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
