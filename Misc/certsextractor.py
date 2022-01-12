#!/usr/bin/env python

import shutil
import os

ca_folder = "certs"
ca_file = "cacert.pem"

ca_folder = os.path.join(os.path.dirname(os.path.realpath(__file__)), ca_folder)

shutil.rmtree(ca_folder, ignore_errors=True)
os.makedirs(ca_folder)

with open(ca_file, "r") as fin:
	data = fin.read()
	certs = data.split("\n\n")
	del certs[0]

	idx = 0
	for cert in certs:
		with open(f"{ca_folder}\\{idx}.pem", "w") as fout:
			fout.write(cert.strip().replace("\r\n", "\n"))
		idx += 1

print("Completed.")
