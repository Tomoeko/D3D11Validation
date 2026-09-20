# Publication review

Publish source and invented test fixtures only. Keep real host configuration,
hardware inventories, raw logs, deployment and package fingerprints, captures,
keys and signed requests in private storage outside Git. `.gitignore` prevents
ordinary accidental additions; it does not remove files already in history.

Before a release:

1. Review tracked filenames, staged changes, commit identities, all branches and
   tags, and historical blobs. Review recognizable host details as well as secrets.
2. Run a secret scanner over all refs, for example
   `gitleaks git --log-opts=--all --redact`. Export the tracked tree with
   `git archive` and scan that separately; never publish an archive of the entire
   working directory. A clean scan does not replace review.
3. Check pull requests, forks, release attachments, workflow logs/artifacts,
   packages, Pages and repository metadata for private material.
4. If private data entered history, rewrite every affected ref and verify an
   independent fresh clone. Keep recovery copies private and outside the release.
   Do not merge old branches back into sanitized history.
5. Do not make a previously sensitive repository public until hosted remnants
   have been addressed. A force-push does not remove cached commits or pull-request
   references. Obtain confirmed removal from the hosting provider, or upload only
   audited history to a new independent repository, keeping the old one private.
   A fork, rename or visibility change alone is not a cleanup operation.

See [GitHub's sensitive-data removal procedure](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository)
for cached-object removal and clone/fork limitations. Never attach private
baselines, raw logs or publisher keys to public issues or support discussions.

Historical operational records have been removed from this source history.
Older revisions contain synthetic replacements for former machine-specific
constants and may lack deployment configuration. Use the current explicit
private-baseline workflow when building; old acceptance summaries do not qualify
a newly built executable. Existing signed deployments retain their original
private provenance and must be requalified when updated.
