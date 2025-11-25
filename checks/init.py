def run_all_checks(path, text):
from .dockerfile_checks import check_dockerfile
from .env_checks import check_env_file
from .nginx_checks import check_nginx
from .k8s_checks import check_k8s
from .terraform_checks import check_terraform
from .iam_checks import check_iam


checks = []
checks.extend(check_dockerfile(path, text))
checks.extend(check_env_file(path, text))
checks.extend(check_nginx(path, text))
checks.extend(check_k8s(path, text))
checks.extend(check_terraform(path, text))
checks.extend(check_iam(path, text))
return checks
