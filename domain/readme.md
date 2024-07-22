## Installation

```shell
python3 -m venv venv_domains
source venv_domains/bin/activate
pip3 install --require-hashes -r install/requirements.txt 
pip3 install --require-hashes -r install/tests_requirements.txt

oxo agent build -f oxo.yaml -o dev --force
docker image list
oxo agent list

pytest tests/ -k "testDomainAgent_whenValidInMessage_emitsVulnerabilityReport"
```