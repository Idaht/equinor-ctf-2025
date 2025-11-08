#!/usr/bin/env python3
from os import listdir, makedirs, walk
from os.path import isfile, join, exists, basename
map_challenge_category_name = {
    "Boot2root": "boot2root",
    "Onsite": "OnSite"}
challenge_categories = []
writeups = ""
for category in listdir("./writeups"):
    if category.startswith(".") or isfile(category):
        continue
    challenge_category = map_challenge_category_name.get(category.capitalize(), category.capitalize())
    challenge_categories.append(challenge_category)
    writeups += f'### {category}\n'
    for chall in listdir(f'./writeups/{category}'):
        chall_url = f'/writeups/{category}/{chall}'.replace(' ', '%20')
        writeups += (f' - **[{chall}]({chall_url})**\n')
        print(writeups)
        for writeup in next(walk(f'./writeups/{category}/{chall}'))[1]:
            wripteup_url = f'/writeups/{category}/{chall}/{writeup}'.replace(' ', '%20')
            writeups += f"\t - [{writeup}]({wripteup_url})  \n"

challenge_categories = sorted(list(set(challenge_categories)), key=str.lower)
table_of_content = ""
for challenge_category in challenge_categories:
    table_of_content += f"- [{challenge_category}](#{challenge_category.lower()})\n"

text = f"""
# Equinor CTF 2025
Writeups and challenges resources for the 2025 Equinor CTF

## How to Contribute

Add a writeup by placing your team folder inside the challenge folder.

Steps:
1. Clone this repository.
2. Find the challenge category: `writeups/<category>/<challenge name>/`
3. Inside that challenge directory create a new folder named your team name
   Example: `writeups/web/CloudNotes/my-team/`
4. Inside your team folder add a README.md containing your writeup. Use markdown.
5. Put any images in the same team folder; reference them with relative paths.

## Table of content

{table_of_content}
---

## Writeups

{writeups}
"""

with open('README.md', 'w') as f:
    f.write(text)
