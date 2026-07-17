<p align="center">
  <h1 align="center"><b>keycred</b></h1>
  <p align="center"><i>Generate and Manage KeyCredentialLinks</i></p>
  <p align="center">
    <a href="https://github.com/RedTeamPentesting/keycred/releases/latest"><img alt="Release" src="https://img.shields.io/github/release/RedTeamPentesting/keycred.svg?style=for-the-badge"></a>
    <a href="https://pkg.go.dev/github.com/RedTeamPentesting/keycred"><img alt="Go Doc" src="https://img.shields.io/badge/godoc-reference-blue.svg?style=for-the-badge"></a>
    <a href="https://github.com/RedTeamPentesting/keycred/actions?workflow=Check"><img alt="GitHub Action: Check" src="https://img.shields.io/github/actions/workflow/status/RedTeamPentesting/keycred/check.yml?branch=main&style=for-the-badge"></a>
    <a href="/LICENSE"><img alt="Software License" src="https://img.shields.io/badge/license-MIT-brightgreen.svg?style=for-the-badge"></a>
  </p>
</p>

---

`keycred` is CLI tool and library that implements the KeyCredentialLink
structures according to [section
2.2.20](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/de61eb56-b75f-4743-b8af-e9be154b47af)
of the Active Directory Technical Specification (MS-ADTS). It also supports
several deviations from the specification that are encountered in practice.

The project also contains a tool to manipulate the `msDS-KeyCredentialLink` LDAP
attribute in order to register KeyCredentialLinks in Active Directory
environments.

## Features

* Supported authentication mechanism: Kerberos (password, NT hash, AES key,
  CCache, PKINIT), mTLS, NTLM (password or NT hash), SimpleBind (password).
* UnPAC-the-Hash: Retrieve the user's NT hash via PKINIT Kerberos
  authentication.
* Cross-platform compatible single binary
* Certificate otherName SAN extensions allows certificates to be used by
  `certipy auth` without specifying username and domain.
* Backup and restore functionality, that is useful when a new KeyCredentialLink
  should be registered for a computer account where another KeyCredentialLink is
  already present.
* Both the library and the tool can generate KeyCredentialLinks that are
  compliant with the rules for validated writes that allow computer accounts to
  modify their own `msDS-KeyCredentialLink` attribute.

## Usage:

The `keycred` CLI tool can be used to create and manage KeyCredentialLinks, and
certificate/key pairs:

```
$ ./keycred --help
keycred is a tool to create and manage KeyCredentialLinks developed by RedTeam Pentesting GmbH

Usage:
  keycred [command]

Available Commands:
  add         Create certificate/key and register it in LDAP
  add-raw     Register a raw DN-Binary string in LDAP
  list        List KeyCredentialLinks of a single user or all users
  remove      Remove a single KeyCredentialLink of a user
  clear       Remove all KeyCredentialLinks of a user
  auth        Authenticate and retrieve the NT hash using PKINIT (requires --pfx)
  burn        Authenticate to obtain hash/ticket and clear KeyCredentialLink (requires --pfx)
  backup      Backup all KeyCredentialLinks of a user
  restore     Restore the KeyCredentialLinks from a backup file
  register    Register the key from an existing PFX file
  parse       Parse a KeyCredentialLink in DN-Binary form
  help        Help about any command
  completion  Generate the autocompletion script for the specified shell

Flags:
      --aes-key hex key       Kerberos AES hex key
      --ccache file           Kerberos CCache file name (defaults to $KRB5CCNAME, currently unset)
      --dc string             Domain controller
      --debug                 Enable debug output
  -h, --help                  help for keycred
  -k, --kerberos              Use Kerberos authentication
  -H, --nt-hash hash          NT hash ('NT', ':NT' or 'LM:NT')
  -p, --password string       Password
      --pfx file              Client certificate and private key as PFX file
      --pfx-password string   Password for PFX file
      --scheme string         Scheme (ldap or ldaps) (default "ldaps")
      --simple-bind           Authenticate with simple bind
      --socks address         SOCKS5 server address
      --start-tls             Negotiate StartTLS before authenticating on regular LDAP connection
  -t, --target user           Target user (default is the authenticating user)
      --timeout duration      LDAP connection timeout (default 5s)
  -u, --user user@domain      Username ('user@domain', 'domain\user', 'domain/user' or 'user')
      --verify                Verify LDAP TLS certificate

Use "keycred [command] --help" for more information about a command.
```

Additionally, this repository also includes `pfxtool`, which can be used to work
with PFX files:

```
$ ./pfxtool --help
A tool to convert certificates and keys from and to PFX files developed by RedTeam Pentesting GmbH

Usage:
  pfxtool [command]

Available Commands:
  join        Create a PFX file by joining a PEM encoded key and cert
  split       Split a PFX file into PEM encoded key and cert
  decrypt     Remove the password from a PFX file
  encrypt     Encrypt the PFX file with a password
  inspect     Inspect the contents of a PFX
  create      Create a certificate/key pair and save it as a PFX file
  version     Print the version
  help        Help about any command
  completion  Generate the autocompletion script for the specified shell

Flags:
  -f, --force             Overwrite existing output files
  -h, --help              help for pfxtool
  -p, --password string   PFX password

Use "pfxtool [command] --help" for more information about a command.
```

## Building

The `keycred` tool can be built as follows:

```sh
go build ./cmd/keycred
```

The PFX handling tool `pfxtool` can be built as follows:

```sh
go build ./cmd/pfxtool
```
