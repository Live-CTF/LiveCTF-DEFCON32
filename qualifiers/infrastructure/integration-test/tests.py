#!/usr/bin/env python3

import io
import json
import os
import tarfile
import time

import jsonschema
import pytest
import requests
from requests.auth import HTTPBasicAuth
from typing import Dict

with open("challenges.schema.json", "r") as fin:
    challenges_schema = json.load(fin)
with open("challenge.schema.json", "r") as fin:
    challenge_schema = json.load(fin)
with open("challenge-scores.schema.json", "r") as fin:
    challenge_scores_schema = json.load(fin)
with open("error.schema.json", "r") as fin:
    error_schema = json.load(fin)
with open("exploit.schema.json", "r") as fin:
    exploit_schema = json.load(fin)
with open("exploit-output.schema.json", "r") as fin:
    exploit_output_schema = json.load(fin)
with open("teams-data.schema.json", "r") as fin:
    teams_schema = json.load(fin)

session = requests.session()
environment = os.environ.get('ENV', 'test')
if environment.lower() == 'production':
    print('Making tests against production')
    session.auth = HTTPBasicAuth('livectf', '[REDACTED]')
    BASE_URL = "https://play.livectf.com/api"
    with open('prod-data.json', 'r') as fin:
        teams = json.load(fin)
else:
    BASE_URL = "http://localhost:9000"
    with open('test-data.json', 'r') as fin:
        teams = json.load(fin)

jsonschema.validate(teams, teams_schema)

exploit_script = """
#/usr/bin/env python3

from pwn import *

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

r = remote(HOST, int(PORT))

r.recvline_contains(b'Give me input: ')
r.sendline(b'WIN')
r.recvline_contains(b'You sent: ')
r.sendline(b'./submitter')
flag = r.recvline_contains(b'LiveCTF{').decode().strip()
log.info('Flag: %s', flag)
"""

dockerfile = """
#FROM debian:bookworm-slim
FROM ubuntu:latest

RUN apt-get update && apt-get install -y python3 python3-pip libffi-dev
RUN pip3 install --break-system-packages pwntools
COPY solve.py .

CMD ["python3", "solve.py"]
"""


def generate_exploit_upload(files: Dict[str, bytes]) -> io.BytesIO:
    tardata = io.BytesIO()
    with tarfile.open(mode="w:gz", fileobj=tardata) as tar_archive:

        for filename, contents in files.items():
            file_info = tarfile.TarInfo(filename)
            file_info.size = len(contents)
            file_data = io.BytesIO(initial_bytes=contents)
            tar_archive.addfile(file_info, file_data)

    tardata.seek(0)
    return tardata  # .getvalue()

def _wait_for_exploit(exploit_id):
    for i in range(5 * 12):
        response = session.get(
            BASE_URL + f"/exploits/{exploit_id}",
            headers={"X-LiveCTF-Token": teams[0]["tickets"]["live-1"]},
        )
        assert response.status_code == 200, response.text
        exploit_status = response.json()
        jsonschema.validate(exploit_status, exploit_schema)
        if exploit_status["status"] in [
            "BuildFailed",
            "RunSolved",
            "RunFailed",
            "Cancelled",
        ]:
            return exploit_status
        time.sleep(5)
    else:
        raise TimeoutError()

    return None


def test_get_challenges():
    """Get list of challenges"""
    response = session.get(BASE_URL + "/challenges/")
    assert response.status_code == 200, response.text
    jsonschema.validate(response.json(), challenges_schema)


def test_get_challenge_open():
    """Get an open challenge"""
    response = session.get(BASE_URL + "/challenges/1001")
    assert response.status_code == 200, response.text
    jsonschema.validate(response.json(), challenge_schema)


def test_get_challenge_open_scores():
    """Get the scores of an open challenge"""
    response = session.get(BASE_URL + "/challenges/1001/scores")
    assert response.status_code == 200, response.text
    jsonschema.validate(response.json(), challenge_scores_schema)


def test_download_challenge_open():
    """Download an open challenge"""
    response = session.get(BASE_URL + "/challenges/1001/download")
    assert response.status_code == 200, response.text
    download_file = io.BytesIO(response.content)
    challenge_archive = tarfile.open(fileobj=download_file)
    assert len(challenge_archive.getmembers()) > 0, len(challenge_archive.getmembers())


def test_get_challenge_released():
    """Get a released but closed challenge"""
    response = session.get(BASE_URL + "/challenges/1003")
    assert response.status_code == 200, response.text
    jsonschema.validate(response.json(), challenge_schema)


def test_get_challenge_released_scores():
    """Get the scores of a released but closed challenge"""
    response = session.get(BASE_URL + "/challenges/1003/scores")
    assert response.status_code == 200, response.text
    jsonschema.validate(response.json(), challenge_scores_schema)


def test_download_challenge_released():
    """Download a released but closed challenge"""
    response = session.get(BASE_URL + "/challenges/1003/download")
    assert response.status_code == 200, response.text
    download_file = io.BytesIO(response.content)
    challenge_archive = tarfile.open(fileobj=download_file)
    assert len(challenge_archive.getmembers()) > 0, len(challenge_archive.getmembers())


def test_get_challenge_unreleased():
    """Try to get an unreleased challenge"""
    response = session.get(BASE_URL + "/challenges/1004")
    assert response.status_code == 403, response.text
    jsonschema.validate(response.json(), error_schema)


def test_download_challenge_unreleased():
    """Try to download an unreleased challenge"""
    response = session.get(BASE_URL + "/challenges/1004/download")
    assert response.status_code == 403, response.text
    jsonschema.validate(response.json(), error_schema)


def test_get_challenge_released_scores():
    """Try to get the scores of an unreleased challenge"""
    response = session.get(BASE_URL + "/challenges/1004/scores")
    assert response.status_code == 403, response.text
    jsonschema.validate(response.json(), error_schema)


def test_challenge_unauth_submit_exploit():
    """Try to submit an exploit without auth token"""
    exploit_archive = generate_exploit_upload(
        {"Dockerfile": dockerfile.encode(), "solve.py": exploit_script.encode()}
    )

    new_exploit1 = session.post(
        BASE_URL + "/challenges/1001",
        files={"exploit": exploit_archive},
    )
    assert new_exploit1.status_code == 403, new_exploit1.text
    jsonschema.validate(new_exploit1.json(), error_schema)


def test_challenge_wrongauth_submit_exploit():
    """Try to submit an exploit with an auth token for the wrong challenge"""
    exploit_archive = generate_exploit_upload(
        {"Dockerfile": dockerfile.encode(), "solve.py": exploit_script.encode()}
    )

    new_exploit1 = session.post(
        BASE_URL + "/challenges/1001",
        headers={"X-LiveCTF-Token": teams[0]["tickets"]["live-2"]},
        files={"exploit": exploit_archive},
    )
    assert new_exploit1.status_code == 403, new_exploit1.text
    jsonschema.validate(new_exploit1.json(), error_schema)


def test_challenge_closed_submit_exploit():
    """Try to submit an exploit for a closed challenge"""
    exploit_files = {
        "Dockerfile": dockerfile.encode(),
        "solve.py": exploit_script.encode(),
    }
    exploit_archive = generate_exploit_upload(exploit_files)

    response = session.post(
        BASE_URL + "/challenges/1003",
        headers={"X-LiveCTF-Token": teams[0]["tickets"]["live-1"]},
        files={"exploit": exploit_archive},
    )
    assert response.status_code == 403, response.text
    jsonschema.validate(response.json(), error_schema)


def test_challenge_unreleased_submit_exploit():
    """Try to submit an exploit for an unreleased challenge"""
    exploit_files = {
        "Dockerfile": dockerfile.encode(),
        "solve.py": exploit_script.encode(),
    }
    exploit_archive = generate_exploit_upload(exploit_files)

    response = session.post(
        BASE_URL + "/challenges/1004",
        headers={"X-LiveCTF-Token": teams[0]["tickets"]["live-1"]},
        files={"exploit": exploit_archive},
    )
    assert response.status_code == 403, response.text
    jsonschema.validate(response.json(), error_schema)


def test_challenge_open_submit_exploit_rate_limit():
    """Try to submit two exploits within the rate limit time"""
    exploit_files = {
        "Dockerfile": dockerfile.encode(),
        "solve.py": exploit_script.encode(),
    }

    exploit_archive = generate_exploit_upload(exploit_files)
    response1 = session.post(
        BASE_URL + "/challenges/1001",
        headers={"X-LiveCTF-Token": teams[0]["tickets"]["live-1"]},
        files={"exploit": exploit_archive},
    )
    assert response1.status_code == 200, response1.text
    exploit1 = response1.json()
    jsonschema.validate(exploit1, exploit_schema)

    exploit_archive = generate_exploit_upload(exploit_files)
    response2 = session.post(
        BASE_URL + "/challenges/1001",
        headers={"X-LiveCTF-Token": teams[0]["tickets"]["live-1"]},
        files={"exploit": exploit_archive},
    )
    assert response2.status_code == 429, response2.text
    error = response2.json()
    jsonschema.validate(error, error_schema)

    exploit_status = _wait_for_exploit(exploit1["exploit_id"])
    assert exploit_status["status"] == "RunSolved", exploit_status["status"]


def test_challenge_open_submit_exploit_pending():
    """Try to submit an exploit after the rate limit while an exploit is still pending"""
    exploit_files = {
        "Dockerfile": dockerfile.encode(),
        "solve.py": exploit_script.encode(),
    }
    exploit_archive = generate_exploit_upload(exploit_files)

    response1 = session.post(
        BASE_URL + "/challenges/1001",
        headers={"X-LiveCTF-Token": teams[0]["tickets"]["live-1"]},
        files={"exploit": exploit_archive},
    )
    assert response1.status_code == 200, response1.text
    exploit1 = response1.json()
    jsonschema.validate(exploit1, exploit_schema)

    time.sleep(65)

    exploit_archive = generate_exploit_upload(exploit_files)
    response2 = session.post(
        BASE_URL + "/challenges/1001",
        headers={"X-LiveCTF-Token": teams[0]["tickets"]["live-1"]},
        files={"exploit": exploit_archive},
    )
    assert response2.status_code == 403, response2.text
    error = response2.json()
    jsonschema.validate(error, error_schema)

    exploit_status = _wait_for_exploit(exploit1["exploit_id"])
    assert exploit_status["status"] == "RunSolved", exploit_status["status"]


def test_challenge_open_submit_exploit_overwrite():
    """Submit a second exploit after the rate limit time and overwrite the pending one"""
    exploit_files = {
        "Dockerfile": dockerfile.encode(),
        "solve.py": exploit_script.encode(),
    }
    exploit_archive = generate_exploit_upload(exploit_files)

    response1 = session.post(
        BASE_URL + "/challenges/1001",
        headers={"X-LiveCTF-Token": teams[0]["tickets"]["live-1"]},
        files={"exploit": exploit_archive},
    )
    assert response1.status_code == 200, response1.text
    exploit1 = response1.json()
    jsonschema.validate(exploit1, exploit_schema)

    time.sleep(65)

    exploit_archive = generate_exploit_upload(exploit_files)
    response2 = session.post(
        BASE_URL + "/challenges/1001",
        headers={"X-LiveCTF-Token": teams[0]["tickets"]["live-1"]},
        files={"exploit": exploit_archive},
        data={"overwrite": "true"},
    )
    assert response2.status_code == 200, response2.text
    exploit2 = response2.json()
    jsonschema.validate(exploit2, exploit_schema)

    exploit_status1 = _wait_for_exploit(exploit1["exploit_id"])
    assert exploit_status1["status"] == "Cancelled", exploit_status1["status"]
    exploit_status2 = _wait_for_exploit(exploit2["exploit_id"])
    assert exploit_status2["status"] == "RunSolved", exploit_status2["status"]


def test_challenge_open_submit_exploit():
    """Submit an exploit for an open challenge"""
    exploit_files = {
        "Dockerfile": dockerfile.encode(),
        "solve.py": exploit_script.encode(),
    }
    exploit_archive = generate_exploit_upload(exploit_files)

    response = session.post(
        BASE_URL + "/challenges/1001",
        headers={"X-LiveCTF-Token": teams[0]["tickets"]["live-1"]},
        files={"exploit": exploit_archive},
    )
    assert response.status_code == 200, response.text
    exploit = response.json()
    jsonschema.validate(exploit, exploit_schema)

    exploit_status = _wait_for_exploit(exploit["exploit_id"])
    assert exploit_status["status"] == "RunSolved", exploit_status["status"]


def test_exploit_get():
    """Submit an exploit and retrieve the exploit info"""
    exploit_files = {
        "Dockerfile": dockerfile.encode(),
        "solve.py": exploit_script.encode(),
    }
    exploit_archive = generate_exploit_upload(exploit_files)

    response1 = session.post(
        BASE_URL + "/challenges/1001",
        headers={"X-LiveCTF-Token": teams[0]["tickets"]["live-1"]},
        files={"exploit": exploit_archive},
    )
    assert response1.status_code == 200, response1.text
    exploit1 = response1.json()
    jsonschema.validate(exploit1, exploit_schema)

    response2 = session.get(
        BASE_URL + f"/exploits/{exploit1['exploit_id']}",
        headers={"X-LiveCTF-Token": teams[0]["tickets"]["live-1"]},
    )
    assert response2.status_code == 200, response2.text
    exploit2 = response2.json()
    jsonschema.validate(exploit2, exploit_schema)

    assert exploit1["exploit_id"] == exploit2["exploit_id"]

    exploit_status = _wait_for_exploit(exploit1["exploit_id"])
    assert exploit_status["status"] == "RunSolved", exploit_status["status"]


def test_exploit_get_other_team():
    """Submit an exploit with team 1 and try to retrieve it with team 2"""
    exploit_files = {
        "Dockerfile": dockerfile.encode(),
        "solve.py": exploit_script.encode(),
    }
    exploit_archive = generate_exploit_upload(exploit_files)

    response1 = session.post(
        BASE_URL + "/challenges/1001",
        headers={"X-LiveCTF-Token": teams[0]["tickets"]["live-1"]},
        files={"exploit": exploit_archive},
    )
    assert response1.status_code == 200, response1.text
    exploit = response1.json()
    jsonschema.validate(exploit, exploit_schema)

    response2 = session.get(
        BASE_URL + f"/exploits/{exploit['exploit_id']}",
        headers={"X-LiveCTF-Token": teams[1]["tickets"]["live-1"]},
    )
    assert response2.status_code == 403, response2.status_code
    error = response2.json()
    jsonschema.validate(error, error_schema)

    exploit_status = _wait_for_exploit(exploit["exploit_id"])
    assert exploit_status["status"] == "RunSolved", exploit_status["status"]


def test_exploit_get_output():
    """Submit an exploit, wait for it to run and retrieve the output"""
    exploit_files = {
        "Dockerfile": dockerfile.encode(),
        "solve.py": exploit_script.encode(),
    }
    exploit_archive = generate_exploit_upload(exploit_files)

    response1 = session.post(
        BASE_URL + "/challenges/1001",
        headers={"X-LiveCTF-Token": teams[0]["tickets"]["live-1"]},
        files={"exploit": exploit_archive},
    )
    assert response1.status_code == 200, response1.text
    exploit = response1.json()
    jsonschema.validate(exploit, exploit_schema)

    exploit_status = _wait_for_exploit(exploit["exploit_id"])
    assert exploit_status["status"] == "RunSolved", exploit_status["status"]

    response2 = session.get(
        BASE_URL + f"/exploits/{exploit['exploit_id']}/output",
        headers={"X-LiveCTF-Token": teams[0]["tickets"]["live-1"]},
    )
    assert response2.status_code == 200, response2.text
    exploit_output = response2.json()
    jsonschema.validate(exploit_output, exploit_output_schema)


def test_exploit_get_output_other_team():
    """Submit an exploit with team 1 and try to retrieve the output with team 2"""
    exploit_files = {
        "Dockerfile": dockerfile.encode(),
        "solve.py": exploit_script.encode(),
    }
    exploit_archive = generate_exploit_upload(exploit_files)

    response1 = session.post(
        BASE_URL + "/challenges/1001",
        headers={"X-LiveCTF-Token": teams[0]["tickets"]["live-1"]},
        files={"exploit": exploit_archive},
    )
    assert response1.status_code == 200, response1.text
    exploit = response1.json()
    jsonschema.validate(exploit, exploit_schema)

    exploit_status = _wait_for_exploit(exploit["exploit_id"])
    assert exploit_status["status"] == "RunSolved", exploit_status["status"]

    response2 = session.get(
        BASE_URL + f"/exploits/{exploit['exploit_id']}/output",
        headers={"X-LiveCTF-Token": teams[1]["tickets"]["live-1"]},
    )
    assert response2.status_code == 403, response2.status_code
    error = response2.json()
    jsonschema.validate(error, error_schema)


if __name__ == "__main__":
    test_get_challenges()
    test_get_challenge_open()
    test_get_challenge_open_scores()
    test_download_challenge_open()
    test_get_challenge_released()
    test_get_challenge_released_scores()
    test_download_challenge_released()
    test_get_challenge_unreleased()
    test_download_challenge_unreleased()
    test_get_challenge_released_scores()
    test_challenge_unauth_submit_exploit()
    test_challenge_wrongauth_submit_exploit()
    test_challenge_closed_submit_exploit()
    test_challenge_unreleased_submit_exploit()
    test_challenge_open_submit_exploit_rate_limit()
    test_challenge_open_submit_exploit_pending()
    test_challenge_open_submit_exploit_overwrite()
    test_challenge_open_submit_exploit()
    test_exploit_get()
    test_exploit_get_other_team()
    test_exploit_get_output()
    test_exploit_get_output_other_team()
