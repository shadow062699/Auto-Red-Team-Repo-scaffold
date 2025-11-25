# clone and install
git clone https://github.com/shadow062699/Auto-Red-Team-Repo-scaffold.git
cd Auto-Red-Team-Repo-scaffold
python -m venv .venv
source .venv/bin/activate
pip install -e .

# scan a project
auto-red-team scan examples/ --format json --output findings.json
#Detects Dockerfiles, .env files, nginx configs, Kubernetes YAML, Terraform .tf files, IAM JSON/YAML.

#Explains vulnerabilities in plain English.

#Classifies severity: Critical / High / Medium / Low / Info.

#Suggests fixes/remediation.
