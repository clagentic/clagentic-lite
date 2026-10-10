"""Tree inference. Heuristics, deliberately few; each is a marker that a path is
exposed or handles sensitive data, found by reading the committed tree. A
marker can only RAISE a dimension (and contradict a profile that says
otherwise), except the test-path fill in stakes.py."""
import posixpath
import re

from .gitstate import git_run
from .globs import compile_glob, glob_escape
from .paths import open_contained_regular

INFER_MAX_FILES = 20000
INFER_MAX_FILE_BYTES = 64 * 1024
INFER_MAX_TOTAL_BYTES = 64 * 1024 * 1024
CHANGED_PATHS_MAX = 5000

_SOURCE_EXTS = (".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".rb", ".java", ".kt", ".php",
                ".rs", ".cs", ".scala", ".ex", ".exs")
_MANIFEST_EXTS = (".yaml", ".yml", ".tpl")
_SCHEMA_EXTS = (".sql", ".prisma", ".proto", ".graphql", ".avsc", ".xsd")
_SCHEMA_DIRS = ("models", "model", "schemas", "schema", "entities", "migrations", "migrate")
_SCHEMA_NAMES = ("models.py", "schema.py", "schema.rb", "models.ts", "models.js")
_WORKFLOW_DIRS = (".github/workflows/", ".gitea/workflows/", ".forgejo/workflows/")
_SKIP_DIRS = (".git", "node_modules", "vendor", ".clagentic", ".venv", "venv", "__pycache__")
_INGRESS_RE = re.compile(
    r"^\s*kind:\s*[\"']?(?:Ingress|IngressRoute|HTTPRoute|VirtualService|Gateway|Route)[\"']?\s*$",
    re.M)
_LOADBALANCER_RE = re.compile(r"^\s*type:\s*[\"']?LoadBalancer[\"']?\s*$", re.M)
# Signs that an ingress or load balancer is internal or sits behind an auth
# layer; with one present the file is not read as a public ingress.
_INTERNAL_SIGNAL_RE = re.compile(
    r"ingressClassName:\s*[\"']?[\w./-]*internal|kubernetes\.io/ingress\.class:\s*[\"']?[\w./-]*internal"
    r"|load-balancer-internal|load-balancer-type:\s*[\"']?internal|\bauth-url\b|\bauth-signin\b"
    r"|oauth2-proxy|whitelist-source-range|allowlist-source-range|loadBalancerSourceRanges",
    re.I)
_EXPOSE_RE = re.compile(r"^\s*EXPOSE\s+\d", re.M | re.I)
_SERVER_RE = re.compile(
    r"\b(?:Flask|FastAPI|Sanic|Starlette|Bottle)\(|\bexpress\(\)|\b[Ff]astify\(|http\.ListenAndServe"
    r"|http\.createServer|\bapp\.listen\(|@(?:app|router|bp|blueprint)\.(?:route|get|post|put|delete)\("
    r"|\bgin\.(?:Default|New)\(|\becho\.New\(|\bfiber\.New\(|\buvicorn\.run\(|Rails\.application\.routes"
    r"|@(?:Get|Post|Put|Delete|Request)Mapping")
_PUBLIC_TRIGGER_RE = re.compile(r"\bpull_request_target\b|\bissue_comment\b")
_PII_RE = re.compile(
    r"\b(?:ssn|social_security(?:_number)?|date_of_birth|dob|birth_?date|passport(?:_number)?"
    r"|national_id|tax_id|drivers?_?licen[cs]e|credit_card|card_number|cvv|iban|account_number"
    r"|email(?:_address)?|phone(?:_number)?|home_address|street_address|salary|diagnosis)\b", re.I)
_PAYMENT_RE = re.compile(
    r"^\s*(?:import|from|use|using)\b[^\n]*\b(?:stripe|braintree|paypal|adyen)\b"
    r"|require\(\s*[\"'](?:stripe|braintree|paypal|adyen)[\"']\s*\)", re.I | re.M)
_CREDENTIAL_RE = re.compile(
    r"\b(?:bcrypt|argon2|scrypt|pbkdf2|password_hash|hashpw|check_password_hash"
    r"|generate_password_hash)\b", re.I)
_SURFACE_AUTH_RE = re.compile(
    r"(?:^|[/_.-])(?:auth|authn|authz|oauth|oidc|saml|sso|login|session|rbac|acl|permission)s?"
    r"(?:[/_.-]|$)", re.I)
_SURFACE_EXPOSURE_RE = re.compile(
    r"(?:ingress|route|gateway|virtualservice|dockerfile|containerfile|docker-compose"
    r"|loadbalancer)", re.I)


def _is_candidate(rel):
    """Whether inference reads REL at all: a manifest, container file, source
    file, workflow or schema file. Anything else can never yield a marker."""
    lowered = posixpath.basename(rel).lower()
    ext = posixpath.splitext(lowered)[1]
    wants_exposure_text = (ext in _MANIFEST_EXTS or lowered.startswith(("dockerfile", "containerfile"))
                           or ext in _SOURCE_EXTS or rel.startswith(_WORKFLOW_DIRS))
    schema_like = (ext in _SCHEMA_EXTS or lowered in _SCHEMA_NAMES
                   or any(part in _SCHEMA_DIRS for part in rel.split("/")[:-1]))
    return wants_exposure_text or schema_like


def list_repo_files(root):
    """Repo-relative paths of the tracked and untracked-but-not-ignored files
    inference can read, up to INFER_MAX_FILES, or None when git cannot list
    them. The candidate filter runs BEFORE the cap, so a tree full of
    non-candidate files cannot push the manifests and sources past it."""
    proc = git_run(root, ["ls-files", "-z", "--cached", "--others", "--exclude-standard"])
    if proc is None or proc.returncode != 0:
        return None
    names = [n for n in proc.stdout.decode("utf-8", "replace").split("\0") if n]
    names = sorted(set(names))
    return [n for n in names
            if not any(part in _SKIP_DIRS for part in n.split("/")[:-1])
            and _is_candidate(n)][:INFER_MAX_FILES]


def _dir_glob(path):
    directory = posixpath.dirname(path)
    return "**" if not directory else glob_escape(directory) + "/**"


def _read_head(root, rel, budget):
    """Up to INFER_MAX_FILE_BYTES of REL as text, or None; BUDGET is a one-item
    list of the bytes still allowed to be read in this scan."""
    if budget[0] <= 0:
        return None
    handle = open_contained_regular(root, rel)
    if handle is None:
        return None
    try:
        data = handle.read(INFER_MAX_FILE_BYTES)
    except OSError:
        return None
    finally:
        handle.close()
    budget[0] -= len(data)
    return data.decode("utf-8", "replace")


def infer_markers(root, files=None):
    """(markers, notes) read from the working tree. A marker is a dict with
    dimension, value (the worse value it implies), glob, compiled, file, why."""
    notes = []
    if files is None:
        files = list_repo_files(root)
    if files is None:
        return [], ["the tree could not be listed; nothing was inferred from it"]
    if len(files) >= INFER_MAX_FILES:
        notes.append("the tree has more than %d files; inference read only the first %d"
                     % (INFER_MAX_FILES, INFER_MAX_FILES))
    budget = [INFER_MAX_TOTAL_BYTES]
    markers = []

    def add(dimension, value, glob, rel, why):
        markers.append({"dimension": dimension, "value": value, "glob": glob,
                        "compiled": compile_glob(glob), "file": rel, "why": why})

    for rel in files:
        name = posixpath.basename(rel)
        lowered = name.lower()
        ext = posixpath.splitext(lowered)[1]
        schema_like = (ext in _SCHEMA_EXTS or lowered in _SCHEMA_NAMES
                       or any(part in _SCHEMA_DIRS for part in rel.split("/")[:-1]))
        if not _is_candidate(rel):
            continue
        text = _read_head(root, rel, budget)
        if text is None:
            continue
        if ext in _MANIFEST_EXTS:
            public = _INGRESS_RE.search(text) or _LOADBALANCER_RE.search(text)
            if public and not _INTERNAL_SIGNAL_RE.search(text):
                what = "an ingress or route" if _INGRESS_RE.search(text) else "a LoadBalancer service"
                add("exposure", "internet", _dir_glob(rel), rel, "%s declares %s with no internal marker" % (rel, what))
        if lowered.startswith(("dockerfile", "containerfile")) and _EXPOSE_RE.search(text):
            add("exposure", "internet", _dir_glob(rel), rel, "%s EXPOSEs a port" % rel)
        if ext in _SOURCE_EXTS and _SERVER_RE.search(text):
            add("exposure", "internet", _dir_glob(rel), rel, "%s starts a server or declares routes" % rel)
        if rel.startswith(_WORKFLOW_DIRS) and _PUBLIC_TRIGGER_RE.search(text):
            add("exposure", "internet", glob_escape(rel), rel,
                "%s runs on a trigger any outsider can cause (pull_request_target or issue_comment)" % rel)
        if schema_like and _PII_RE.search(text):
            add("data", "regulated_or_customer", _dir_glob(rel), rel,
                "%s defines PII-shaped fields" % rel)
        if ext in _SOURCE_EXTS and (_PAYMENT_RE.search(text) or _CREDENTIAL_RE.search(text)):
            add("data", "regulated_or_customer", _dir_glob(rel), rel,
                "%s handles payments or credentials" % rel)
    return markers, notes


def changed_paths(root, base, wanted=None):
    """Paths that differ between BASE and the working tree, plus untracked
    ones: what the gated change touches. [] when BASE is unknown. None when a
    git call failed or timed out: "cannot tell" is not "nothing changed", and
    the caller must resolve it to the worst case. WANTED, when given, filters
    BEFORE the cap, so a large change cannot push the paths the caller cares
    about past CHANGED_PATHS_MAX."""
    if not base:
        return []
    paths = set()
    for args in (["diff", "--name-only", "-z", base], ["ls-files", "-z", "--others", "--exclude-standard"]):
        proc = git_run(root, args)
        if proc is None or proc.returncode != 0:
            return None
        paths.update(n for n in proc.stdout.decode("utf-8", "replace").split("\0") if n)
    if wanted is not None:
        paths = {n for n in paths if wanted(n)}
    return sorted(paths)[:CHANGED_PATHS_MAX]


def touches_exposure_surface(path, marker_files):
    """Whether PATH is part of what the profile's exposure and data claims
    describe: an ingress, route or service manifest, a container or workflow
    definition, auth code, a data schema, or a file inference drew a marker
    from."""
    if path in marker_files:
        return True
    lowered = path.lower()
    name = posixpath.basename(lowered)
    if _SURFACE_EXPOSURE_RE.search(name) or path.startswith(_WORKFLOW_DIRS):
        return True
    if _SURFACE_AUTH_RE.search(lowered):
        return True
    ext = posixpath.splitext(name)[1]
    return (ext in _SCHEMA_EXTS or name in _SCHEMA_NAMES
            or any(part in _SCHEMA_DIRS for part in lowered.split("/")[:-1]))
