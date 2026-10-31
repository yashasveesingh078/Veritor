"""The catalog of rules. Severity and confidence are chosen where each rule fires."""

from dataclasses import dataclass

from app.analysis.models import FindingCategory as Category


@dataclass(frozen=True)
class Rule:
    title: str
    category: Category
    recommendation: str


_REVIEW_FLOW = "Check what this value is and where it comes from."

RULES: dict[str, Rule] = {
    "EXEC-001": Rule(
        "Dynamic code execution of a computed value",
        Category.DYNAMIC_EXECUTION,
        f"{_REVIEW_FLOW} Code built at runtime cannot be reviewed from the source.",
    ),
    "EXEC-002": Rule(
        "Dynamic code execution of a fixed string",
        Category.DYNAMIC_EXECUTION,
        "Usually a known idiom such as Function('return this')(). Confirm the string is harmless.",
    ),
    "EXEC-003": Rule(
        "Decoded data is executed as code",
        Category.DYNAMIC_EXECUTION,
        "Treat as hidden code until reviewed. Decode the payload without running it, and read it.",
    ),
    "EXEC-004": Rule(
        "Module loaded from a computed name",
        Category.DYNAMIC_EXECUTION,
        "Check which modules this can load. Bundlers and plugin systems do this legitimately.",
    ),
    "EXEC-005": Rule(
        "Module loaded from a decoded name",
        Category.DYNAMIC_EXECUTION,
        "Treat as an attempt to hide a dependency. Decode the name without running it.",
    ),
    "PROC-001": Rule(
        "Imports child_process",
        Category.CHILD_PROCESS,
        "No action needed on its own. Check how the module is used.",
    ),
    "PROC-002": Rule(
        "Starts a fixed command",
        Category.CHILD_PROCESS,
        "Confirm the command is expected for what this package does.",
    ),
    "PROC-003": Rule(
        "Starts a computed command",
        Category.CHILD_PROCESS,
        f"{_REVIEW_FLOW} If it can contain outside input, it can run arbitrary commands.",
    ),
    "PROC-004": Rule(
        "Starts a command that fetches, decodes or tunnels",
        Category.CHILD_PROCESS,
        "Do not install until reviewed. Find out what the command downloads or runs.",
    ),
    "PROC-005": Rule(
        "Reaches process internals directly",
        Category.CHILD_PROCESS,
        "Packages rarely need process.binding. Find out why this one avoids child_process.",
    ),
    "ENV-001": Rule(
        "Reads an environment variable",
        Category.ENVIRONMENT_ACCESS,
        "No action needed on its own. Most packages read configuration this way.",
    ),
    "ENV-002": Rule(
        "Reads a credential-like environment variable",
        Category.ENVIRONMENT_ACCESS,
        "Confirm the package has a reason to read this, and check where the value goes.",
    ),
    "ENV-003": Rule(
        "Uses the whole environment",
        Category.ENVIRONMENT_ACCESS,
        "Check where the object goes. Passing it to a child process is common. Sending it is not.",
    ),
    "NET-001": Rule(
        "Makes a network call",
        Category.NETWORK,
        "No action needed on its own. Confirm the package is expected to use the network.",
    ),
    "NET-002": Rule(
        "Calls a data-collection service or fixed public IP address",
        Category.NETWORK,
        "Do not install until reviewed. Packages rarely have a reason to call these.",
    ),
    "NET-003": Rule(
        "Contains the address of a data-collection service",
        Category.NETWORK,
        "Find where this address is used. It may be built into a request elsewhere.",
    ),
    "OBF-001": Rule(
        "Identifiers match common obfuscator output",
        Category.OBFUSCATION,
        "Compare with the source, because obfuscated code cannot be reviewed as published.",
    ),
    "OBF-002": Rule(
        "Long encoded string",
        Category.OBFUSCATION,
        "Decode it without running it. It is often embedded data, but it can also hide code.",
    ),
    "OBF-003": Rule(
        "String built from character codes",
        Category.OBFUSCATION,
        "Work out the resulting text without running it, and check how it is used.",
    ),
    "OBF-004": Rule(
        "Decodes data at runtime",
        Category.OBFUSCATION,
        "No action needed on its own. Check whether the output reaches code execution.",
    ),
    "FS-001": Rule(
        "Accesses a credential or secrets path",
        Category.FILESYSTEM,
        "Confirm why the package needs this file, and check where its contents go.",
    ),
    "FS-002": Rule(
        "Writes to a credential or startup path",
        Category.FILESYSTEM,
        "Do not install until reviewed. This can grant lasting access to the machine.",
    ),
    "LIFE-001": Rule(
        "Install script is not in the source",
        Category.LIFECYCLE_SCRIPT,
        "Do not install until reviewed. It runs automatically and the repository can't explain it.",
    ),
    "LIFE-002": Rule(
        "Install script differs from the source",
        Category.LIFECYCLE_SCRIPT,
        "Compare the two versions. This code runs automatically on install.",
    ),
    "LIFE-003": Rule(
        "Install script matches the source",
        Category.LIFECYCLE_SCRIPT,
        "Confirm the package needs to run code on install.",
    ),
    "LIFE-004": Rule(
        "Registry metadata and tarball disagree about install scripts",
        Category.LIFECYCLE_SCRIPT,
        "Trust the tarball. Tools that read only registry metadata can miss this script.",
    ),
    "LIFE-005": Rule(
        "Install script fetches, decodes or runs inline code",
        Category.LIFECYCLE_SCRIPT,
        "Do not install until reviewed. Find out what this command downloads or runs.",
    ),
    "LIFE-006": Rule(
        "binding.gyp was added",
        Category.LIFECYCLE_SCRIPT,
        "npm can build this on install even with no install script. Review the native code.",
    ),
    "LIFE-007": Rule(
        "Install script cannot be traced to source",
        Category.LIFECYCLE_SCRIPT,
        "Review the script directly, because no source commit was established to compare it with.",
    ),
    "CORR-001": Rule(
        "Credentials and network access in one file",
        Category.CORRELATED_BEHAVIOUR,
        "Trace whether the credential can reach the network call. This pattern can exfiltrate.",
    ),
    "CORR-002": Rule(
        "Runtime decoding and code or command execution in one file",
        Category.CORRELATED_BEHAVIOUR,
        "Trace whether decoded data reaches execution. This pattern can hide a payload.",
    ),
    "CORR-003": Rule(
        "Network access and command execution in one file",
        Category.CORRELATED_BEHAVIOUR,
        "Trace whether downloaded data reaches execution. This pattern can download and run code.",
    ),
    "CORR-004": Rule(
        "Obfuscated code with sensitive behaviour",
        Category.CORRELATED_BEHAVIOUR,
        "Compare with the source. Hiding code that executes or sends data is a strong warning.",
    ),
    "CORR-005": Rule(
        "Sensitive behaviour runs at install",
        Category.CORRELATED_BEHAVIOUR,
        "Do not install until reviewed. This runs automatically, with the user's permissions.",
    ),
}
