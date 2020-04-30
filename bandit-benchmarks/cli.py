#!/usr/bin/env python3
# bandit-benchmark
# Copyright(C) 2020 Kevin Postlethwait
#
# This program is free software: you can redistribute it and / or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

"""Use bandit as a static security benchmark"""

import logging
import os
import tempfile
import subprocess
import tarfile
import json
from subprocess import PIPE
from sys import getsizeof
import sys

import click
from thoth.common import init_logging

HIGH_SEVERITY_WEIGHT=6
MEDIUM_SEVERITY_WEIGHT=3
LOW_SEVERITY_WEIGHT=1

HIGH_CONFIDENCE_WEIGHT=1
MEDIUM_CONFIDENCE_WEIGHT=0.5
LOW_CONFIDENCE_WEIGHT=0.25

init_logging()

# we need to add options for bandit

@click.command()
@click.option('--package_name', help="name of python package on package index")
@click.option('--package_version', help="specific version to dig into")
@click.option('--pypi_index', default="https://pypi.org/simple")
def analyze_package(package_name: str, package_version: str, pypi_index: str):
    # pip download into temp dir
    with tempfile.TemporaryDirectory() as tempdir:
        command = ["pip", "download", f"{package_name}=={package_version}",
                    "--no-binary=:all:", "--no-deps", "-d",  tempdir]
        # add options for platform, py version, implemenation...=
        subprocess.run(command)
        # temp-dir
        #   |-> some-file.tar.gz     (it will always look like this because of the no-binary option)
        for file in os.listdir(tempdir):
            if file.endswith(".tar.gz"):
                full_path = os.path.join(tempdir, file)
                tar = tarfile.open(full_path, "r:gz")
                tar.extractall(os.path.join(tempdir, "package"))
        output = subprocess.run(["bandit", "-r", "-f", "json", os.path.join(tempdir, "package")], stdout=PIPE).stdout
        output = output.decode()
        json_output = json.loads(output)

        score = 0       # score accumulator
        for i in json_output["metrics"]:    # Last element is the totals using it would cause everything to be double counted
            if i == "_totals":
                continue
            curr = json_output["metrics"][i]
            divisor = (curr['CONFIDENCE.HIGH'] + curr['CONFIDENCE.MEDIUM']
                        + curr['CONFIDENCE.LOW'] + curr['CONFIDENCE.UNDEFINED'])
            if divisor == 0:
                continue       # Skip elements with 0 otherwise divide by zero
            priority = (HIGH_SEVERITY_WEIGHT*(curr['SEVERITY.HIGH'] + curr['SEVERITY.UNDEFINED'])
                            + MEDIUM_SEVERITY_WEIGHT*curr['SEVERITY.MEDIUM']
                            + LOW_SEVERITY_WEIGHT*curr['SEVERITY.LOW'])
            confidence = (HIGH_CONFIDENCE_WEIGHT*(curr['CONFIDENCE.HIGH'] + curr['CONFIDENCE.UNDEFINED'])
                            + MEDIUM_CONFIDENCE_WEIGHT*curr['CONFIDENCE.MEDIUM']
                            + LOW_CONFIDENCE_WEIGHT*curr['CONFIDENCE.LOW'])
            confidence = confidence / divisor
            score += priority * confidence

        print(score)        # I can almost guarantee that score is directly correlated with lines of code
                            # This may be okay or we can work LOC into the metrics somehow

if __name__ == "__main__":
    analyze_package()