# Update here
challenges: challenge-test-challenge \
	challenge-process_vm_readv-me-maybe \
	challenge-shiny-shells \
	challenge-ndles \
	challenge-durnk \
	challenge-trickshot \
	challenge-qrackme

###############################################################################
# test-challenge

challenge-test-challenge: handouts/quals-test-challenge-handout.tar.gz

handouts/quals-test-challenge-handout.tar.gz: $(shell find test-challenge/challenge -type f)
	DOCKER_BUILDKIT=1 docker build -t livectf:quals-test-challenge test-challenge/challenge
	./extract-handout.sh quals-test-challenge

run-test-challenge: challenge-test-challenge
	./test-run.sh quals-test-challenge

solution-test-challenge: challenge-test-challenge $(shell find test-challenge/solution -type f)
	DOCKER_BUILDKIT=1 docker build -t livectf:quals-test-challenge_exploit test-challenge/solution
	./test-solution.sh quals-test-challenge

push-test-challenge-remote: handouts/quals-test-challenge-handout.tar.gz
	DOCKER_BUILDKIT=1 docker build -t livectf:quals-test-challenge test-challenge/challenge
	docker tag livectf:quals-test-challenge localhost:6000/b4f31f6edb2fdec8-test-challenge:latest
	docker push localhost:6000/b4f31f6edb2fdec8-test-challenge:latest
	gcloud storage cp handouts/quals-test-challenge-handout.tar.gz 'gs://livectf24-challenges/test-challenge.tgz'

push-test-challenge-pretest:
	DOCKER_BUILDKIT=1 docker build -t livectf:quals-test-challenge test-challenge/challenge
	docker tag livectf:quals-test-challenge localhost:6000/b4f31f6edb2fdec8-livectf_challenge1:latest
	docker push localhost:6000/b4f31f6edb2fdec8-livectf_challenge1:latest

###############################################################################
# process_vm_readv-me-maybe

challenge-process_vm_readv-me-maybe: handouts/quals-process_vm_readv-me-maybe-handout.tar.gz

handouts/quals-process_vm_readv-me-maybe-handout.tar.gz: $(shell find process_vm_readv-me-maybe/challenge -type f)
	DOCKER_BUILDKIT=1 docker build -t livectf:quals-process_vm_readv-me-maybe process_vm_readv-me-maybe/challenge
	./extract-handout.sh quals-process_vm_readv-me-maybe

run-process_vm_readv-me-maybe: challenge-process_vm_readv-me-maybe
	./test-run.sh quals-process_vm_readv-me-maybe

solution-process_vm_readv-me-maybe: challenge-process_vm_readv-me-maybe $(shell find process_vm_readv-me-maybe/solution -type f)
	DOCKER_BUILDKIT=1 docker build -t livectf:quals-process_vm_readv-me-maybe_exploit process_vm_readv-me-maybe/solution
	./test-solution.sh quals-process_vm_readv-me-maybe

push-process_vm_readv-me-maybe-remote: handouts/quals-process_vm_readv-me-maybe-handout.tar.gz
	DOCKER_BUILDKIT=1 docker build -t livectf:quals-process_vm_readv-me-maybe process_vm_readv-me-maybe/challenge
	docker tag livectf:quals-process_vm_readv-me-maybe localhost:6000/b4f31f6edb2fdec8-process_vm_readv-me-maybe:latest
	docker push localhost:6000/b4f31f6edb2fdec8-process_vm_readv-me-maybe:latest
	gcloud storage cp handouts/quals-process_vm_readv-me-maybe-handout.tar.gz 'gs://livectf24-challenges/process_vm_readv-me-maybe.tgz'

push-process_vm_readv-me-maybe-pretest:
	DOCKER_BUILDKIT=1 docker build -t livectf:quals-process_vm_readv-me-maybe process_vm_readv-me-maybe/challenge
	docker tag livectf:quals-process_vm_readv-me-maybe localhost:6000/b4f31f6edb2fdec8-livectf_challenge1:latest
	docker push localhost:6000/b4f31f6edb2fdec8-livectf_challenge1:latest

###############################################################################
# shiny-shells

challenge-shiny-shells: handouts/quals-shiny-shells-handout.tar.gz

handouts/quals-shiny-shells-handout.tar.gz: $(shell find shiny-shells/challenge -type f)
	DOCKER_BUILDKIT=1 docker build -t livectf:quals-shiny-shells shiny-shells/challenge
	./extract-handout.sh quals-shiny-shells

run-shiny-shells: challenge-shiny-shells
	./test-run.sh quals-shiny-shells

solution-shiny-shells: challenge-shiny-shells $(shell find shiny-shells/solution -type f)
	DOCKER_BUILDKIT=1 docker build -t livectf:quals-shiny-shells_exploit shiny-shells/solution
	./test-solution.sh quals-shiny-shells

push-shiny-shells-remote: handouts/quals-shiny-shells-handout.tar.gz
	DOCKER_BUILDKIT=1 docker build -t livectf:quals-shiny-shells shiny-shells/challenge
	docker tag livectf:quals-shiny-shells localhost:6000/b4f31f6edb2fdec8-shiny-shells:latest
	docker push localhost:6000/b4f31f6edb2fdec8-shiny-shells:latest
	gcloud storage cp handouts/quals-shiny-shells-handout.tar.gz 'gs://livectf24-challenges/shiny-shells.tgz'

push-shiny-shells-pretest:
	DOCKER_BUILDKIT=1 docker build -t livectf:quals-shiny-shells shiny-shells/challenge
	docker tag livectf:quals-shiny-shells localhost:6000/b4f31f6edb2fdec8-livectf_challenge1:latest
	docker push localhost:6000/b4f31f6edb2fdec8-livectf_challenge1:latest

###############################################################################
# durnk

challenge-durnk: handouts/quals-durnk-handout.tar.gz

handouts/quals-durnk-handout.tar.gz: $(shell find durnk/challenge -type f)
	DOCKER_BUILDKIT=1 docker build -t livectf:quals-durnk durnk/challenge
	./extract-handout.sh quals-durnk

run-durnk: challenge-durnk
	./test-run.sh quals-durnk

solution-durnk: challenge-durnk $(shell find durnk/solution -type f)
	DOCKER_BUILDKIT=1 docker build -t livectf:quals-durnk_exploit durnk/solution
	./test-solution.sh quals-durnk

push-durnk-remote: handouts/quals-durnk-handout.tar.gz
	DOCKER_BUILDKIT=1 docker build -t livectf:quals-durnk durnk/challenge
	docker tag livectf:quals-durnk localhost:6000/b4f31f6edb2fdec8-durnk:latest
	docker push localhost:6000/b4f31f6edb2fdec8-durnk:latest
	gcloud storage cp handouts/quals-durnk-handout.tar.gz 'gs://livectf24-challenges/durnk.tgz'

push-durnk-pretest:
	DOCKER_BUILDKIT=1 docker build -t livectf:quals-durnk durnk/challenge
	docker tag livectf:quals-durnk localhost:6000/b4f31f6edb2fdec8-livectf_challenge1:latest
	docker push localhost:6000/b4f31f6edb2fdec8-livectf_challenge1:latest

###############################################################################
# ndles

challenge-ndles: handouts/quals-ndles-handout.tar.gz

handouts/quals-ndles-handout.tar.gz: $(shell find ndles/challenge -type f)
	DOCKER_BUILDKIT=1 docker build -t livectf:quals-ndles ndles/challenge
	./extract-handout.sh quals-ndles

run-ndles: challenge-ndles
	./test-run.sh quals-ndles

solution-ndles: challenge-ndles $(shell find ndles/solution -type f)
	DOCKER_BUILDKIT=1 docker build -t livectf:quals-ndles_exploit ndles/solution
	./test-solution.sh quals-ndles

push-ndles-remote: handouts/quals-ndles-handout.tar.gz
	DOCKER_BUILDKIT=1 docker build -t livectf:quals-ndles ndles/challenge
	docker tag livectf:quals-ndles localhost:6000/b4f31f6edb2fdec8-ndles:latest
	docker push localhost:6000/b4f31f6edb2fdec8-ndles:latest
	gcloud storage cp handouts/quals-ndles-handout.tar.gz 'gs://livectf24-challenges/ndles.tgz'

push-ndles-pretest:
	DOCKER_BUILDKIT=1 docker build -t livectf:quals-ndles ndles/challenge
	docker tag livectf:quals-ndles localhost:6000/b4f31f6edb2fdec8-livectf_challenge1:latest
	docker push localhost:6000/b4f31f6edb2fdec8-livectf_challenge1:latest

###############################################################################
# trickshot

challenge-trickshot: handouts/quals-trickshot-handout.tar.gz

handouts/quals-trickshot-handout.tar.gz: $(shell find trickshot/challenge -type f)
	DOCKER_BUILDKIT=1 docker build -t livectf:quals-trickshot trickshot/challenge
	./extract-handout.sh quals-trickshot

run-trickshot: challenge-trickshot
	./test-run.sh quals-trickshot

solution-trickshot: challenge-trickshot $(shell find trickshot/solution -type f)
	DOCKER_BUILDKIT=1 docker build -t livectf:quals-trickshot_exploit trickshot/solution
	./test-solution.sh quals-trickshot

push-trickshot-remote: handouts/quals-trickshot-handout.tar.gz
	DOCKER_BUILDKIT=1 docker build -t livectf:quals-trickshot trickshot/challenge
	docker tag livectf:quals-trickshot localhost:6000/b4f31f6edb2fdec8-trickshot:latest
	docker push localhost:6000/b4f31f6edb2fdec8-trickshot:latest
	gcloud storage cp handouts/quals-trickshot-handout.tar.gz 'gs://livectf24-challenges/trickshot.tgz'

push-trickshot-pretest:
	DOCKER_BUILDKIT=1 docker build -t livectf:quals-trickshot trickshot/challenge
	docker tag livectf:quals-trickshot localhost:6000/b4f31f6edb2fdec8-livectf_challenge1:latest
	docker push localhost:6000/b4f31f6edb2fdec8-livectf_challenge1:latest

###############################################################################
# qrackme

challenge-qrackme: handouts/quals-qrackme-handout.tar.gz

handouts/quals-qrackme-handout.tar.gz: $(shell find qrackme/challenge -type f)
	DOCKER_BUILDKIT=1 docker build -t livectf:quals-qrackme qrackme/challenge
	./extract-handout.sh quals-qrackme

run-qrackme: challenge-qrackme
	./test-run.sh quals-qrackme

solution-qrackme: challenge-qrackme $(shell find qrackme/solution -type f)
	DOCKER_BUILDKIT=1 docker build -t livectf:quals-qrackme_exploit qrackme/solution
	./test-solution.sh quals-qrackme

push-qrackme-remote: handouts/quals-qrackme-handout.tar.gz
	DOCKER_BUILDKIT=1 docker build -t livectf:quals-qrackme qrackme/challenge
	docker tag livectf:quals-qrackme localhost:6000/b4f31f6edb2fdec8-qrackme:latest
	docker push localhost:6000/b4f31f6edb2fdec8-qrackme:latest
	gcloud storage cp handouts/quals-qrackme-handout.tar.gz 'gs://livectf24-challenges/qrackme.tgz'

push-qrackme-pretest:
	DOCKER_BUILDKIT=1 docker build -t livectf:quals-qrackme qrackme/challenge
	docker tag livectf:quals-qrackme localhost:6000/b4f31f6edb2fdec8-livectf_challenge1:latest
	docker push localhost:6000/b4f31f6edb2fdec8-livectf_challenge1:latest

###############################################################################

# Update here
push-test-challenges-local:
	docker tag livectf:quals-test-challenge 172.17.0.1:5000/b4f31f6edb2fdec8-livectf_challenge1:latest
	docker push 172.17.0.1:5000/b4f31f6edb2fdec8-livectf_challenge1:latest
	docker tag livectf:quals-test-challenge 172.17.0.1:5000/b4f31f6edb2fdec8-livectf_the_cool_challenge:latest
	docker push 172.17.0.1:5000/b4f31f6edb2fdec8-livectf_the_cool_challenge:latest
	docker tag livectf:quals-test-challenge 172.17.0.1:5000/b4f31f6edb2fdec8-livectf_difficult_challenge:latest
	docker push 172.17.0.1:5000/b4f31f6edb2fdec8-livectf_difficult_challenge:latest
	docker tag livectf:quals-test-challenge 172.17.0.1:5000/b4f31f6edb2fdec8-livectf_doom:latest
	docker push 172.17.0.1:5000/b4f31f6edb2fdec8-livectf_doom:latest

# Update here
.PHONY: challenges \
		challenge-test-challenge \
		run-test-challenge \
		solution-test-challenge \
		challenge-durnk \
		run-durnk \
		solution-durnk \
		challenge-process_vm_readv-me-maybe \
		run-process_vm_readv-me-maybe \
		solution-process_vm_readv-me-maybe \
		challenge-shiny-shells \
		run-shiny-shells \
		solution-shiny-shells \
		challenge-ndles \
		run-ndles \
		solution-ndles \
		challenge-trickshot \
		run-trickshot \
		solution-trickshot \
		challenge-qrackme \
		run-qrackme \
		solution-qrackme \
		push-test-challenges
