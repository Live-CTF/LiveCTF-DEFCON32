CTF_STARTED=true

default: deploy

deploy: mitogen
	ansible-playbook -i ../terraform/hosts.yml livectf-playbook.yml -e ctf_started=$(CTF_STARTED)

upgrade: mitogen
	ansible-playbook -i ../terraform/hosts.yml livectf-playbook.yml -e upgrade_runner=true -e upgrade_builder=true -e upgrade_web=true -e upgrade_api=true -e ctf_started=$(CTF_STARTED)

upgrade-web: mitogen
	ansible-playbook -i ../terraform/hosts.yml livectf-playbook.yml -e upgrade_web=true -e upgrade_api=true -e ctf_started=$(CTF_STARTED)

fix-playbook: mitogen
	ansible-playbook -i ../terraform/hosts.yml fix-playbook.yml --limit web -e upgrade_runner=true -e upgrade_builder=true -e upgrade_web=true -e upgrade_api=true -e ctf_started=$(CTF_STARTED)

upgrade-runner: mitogen
	ansible-playbook -i ../terraform/hosts.yml livectf-playbook.yml --limit runner -e upgrade_runner=true -e ctf_started=$(CTF_STARTED)

upgrade-builder: mitogen
	ansible-playbook -i ../terraform/hosts.yml livectf-playbook.yml --limit builder -e upgrade_builder=true -e ctf_started=$(CTF_STARTED)

dev: mitogen
	ansible-playbook -i ../terraform/hosts.yml dev-playbook.yml -e upgrade_runner=true -e upgrade_builder=true -e upgrade_web=true -e upgrade_api=true -e ctf_started=$(CTF_STARTED)

prepare:
	docker run --rm -d -p 127.0.0.1:5001:5000 -p 172.17.0.1:5001:5000 --name registry registry:2

cleanup:
	docker stop registry

dependencies:
	pip3 install -r requirements.txt --upgrade
	ansible-galaxy collection install --upgrade community.general

inventory: mitogen
	ansible-inventory -i ../terraform/hosts.yml --list

mitogen: mitogen-0.3.7

mitogen-0.3.7:
	wget https://files.pythonhosted.org/packages/source/m/mitogen/mitogen-0.3.7.tar.gz
	tar xf mitogen-0.3.7.tar.gz
	rm mitogen-0.3.7.tar.gz

.PHONY: default dependencies mitogen deploy prepare cleanup inventory
