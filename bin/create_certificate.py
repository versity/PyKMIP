#!/usr/bin/env python3

#from __future__ import print_function

import os
import sys
import argparse

from cryptography import x509
from cryptography.hazmat import backends
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import datetime

ORGANIZATION_NAME = u"Test, Inc."

def create_rsa_private_key(key_size=2048, public_exponent=65537):
    private_key = rsa.generate_private_key(
        public_exponent=public_exponent,
        key_size=key_size,
        backend=backends.default_backend()
    )
    return private_key


def create_self_signed_certificate(subject_name, private_key, days_valid=365):

    subject = x509.Name([
        x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, ORGANIZATION_NAME),
        x509.NameAttribute(x509.NameOID.COMMON_NAME, subject_name)
    ])

    certificate = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        subject
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=days_valid)
    ).sign(private_key, hashes.SHA256(), backends.default_backend())

    return certificate


def create_certificate(subject_name,
                       private_key,
                       signing_certificate,
                       signing_key,
                       days_valid=365,
                       client_auth=False):

    subject = x509.Name([
        x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, ORGANIZATION_NAME),
        x509.NameAttribute(x509.NameOID.COMMON_NAME, subject_name)
    ])

    builder = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        signing_certificate.subject
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=days_valid)
    )

    if client_auth:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=True
        )

    certificate = builder.sign(
        signing_key,
        hashes.SHA256(),
        backends.default_backend()
    )

    return certificate

def read_private_key(path):
    with open(path, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=backends.default_backend()
        )
    return private_key


def write_private_key(path, key):
    with open(path, "wb") as f:
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        f.write(pem)


def read_public_certificate(path):
    with open(path, "rb") as f:
        public_certificate = x509.load_pem_x509_certificate(
            f.read(),
            backend=backends.default_backend()
        )
    return public_certificate


def write_public_certificate(path, certificate):
    with open(path, "wb") as f:
        pem = certificate.public_bytes(
            serialization.Encoding.PEM
        )
        f.write(pem) 


def create_root(certs):

    root_key = create_rsa_private_key()
    root_certificate = create_self_signed_certificate(
        u"Root CA",
        root_key
    )

    write_private_key(root_key_file, root_key)
    write_public_certificate(root_certificate_file, root_certificate)

    return root_certificate, root_key


def create_server(certs):

    server_key = create_rsa_private_key()

    server_certificate = create_certificate(
        u"Server Certificate",
        server_key,
        root_certificate,
        root_key
    )

    write_private_key(server_key_file, server_key)
    write_public_certificate(server_certificate_file, server_certificate)

    return server_certificate, server_key


def generate_client(certs, name):

    client_certificate_file = certs + "/" + "client_certificate_" + name.replace(" ", "_")  + ".pem"
    client_key_file = certs + "/" + "client_key_" + name.replace(" ", "_")  + ".pem"

    client_key = create_rsa_private_key()
    client_certificate = create_certificate(
        name,   # XXX - .encode("utf-8"),   # XXX - name.decode("utf-8"),
        client_key,
        root_certificate,
        root_key,
        client_auth=True
    )

    write_private_key(client_key_file, client_key)
    write_public_certificate(client_certificate_file, client_certificate)


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Certificate Gnerator')
    parser.add_argument('-c', '--certs', action='store',
                        default='./certs',
                        help='Certificates directory')
    parser.add_argument('-n', '--name', action='store',
                        help='Subject name (user).')
    parser.add_argument('-o', '--organization', action='store',
                        help='Name of the organization.')
    parser.add_argument('-r', '--root', action='store_true',
                        help='Generate root certificate.')
    parser.add_argument('-s', '--server', action='store_true',
                        help='Generate server certificate.')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Use verbose logging.')
    arguments = parser.parse_args()

    verbose = arguments.verbose

    print(arguments)

    certs = arguments.certs

    if not os.path.isdir(arguments.certs):
        print('Certificates directory {} must exist'.format(arguments.certs))
        sys.exit(1)

    root_certificate_file = certs + "/" + "root_certificate.pem"
    root_key_file = certs + "/" + "root_key.pem"
    if arguments.root:
        root_certificate, root_key = create_root(certs)
    else:
        root_certificate = read_public_certificate(root_certificate_file)
        root_key = read_private_key(root_key_file)

    server_certificate_file = certs + "/" + "server_certificate.pem"
    server_key_file = certs + "/" + "server_key.pem"
    if arguments.server:
        server_certificate, server_key = create_server(certs)
    else:
        server_certificate = read_public_certificate(server_certificate_file)
        server_key = read_private_key(server_key_file)
    
    if arguments.name:
        generate_client(certs, arguments.name)

