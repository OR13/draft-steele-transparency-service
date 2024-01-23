# Transparency Service

This is the working area for the individual Internet-Draft, "Transparency Service".

* [Editor's Copy](https://OR13.github.io/draft-steele-transparency-service/#go.draft-steele-transparency-service.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-steele-transparency-service)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-steele-transparency-service)
* [Compare Editor's Copy to Individual Draft](https://OR13.github.io/draft-steele-transparency-service/#go.draft-steele-transparency-service.diff)

This document describes an HTTP and COSE based service with similar properties to CT, KT and SCITT.

## Relation to Certificate Transparency

[RFC9162](https://datatracker.ietf.org/doc/rfc9162/) describes the Certificate Transparency (CT) protocol for publicly logging the existence of Transport Layer Security (TLS) server certificates as they are issued or observed, in a manner that allows anyone to audit certification authority (CA) activity and notice the issuance of suspect certificates as well as to audit the certificate logs themselves.

## Relation to Key Transparency Architecture

[Key Transparency Architecture](https://datatracker.ietf.org/doc/draft-ietf-keytrans-architecture/) defines the terminology and interaction patterns involved in the deployment of Key Transparency (KT) in a general secure group messaging infrastructure, and specifies the security properties that the protocol provides.

## Relation to SCITT Architecture

The [SCITT Architecture](https://github.com/ietf-wg-scitt/draft-ietf-scitt-architecture) describes an approach to developing transparency services focused on securing digital supply chains.


## Contributing

See the
[guidelines for contributions](https://github.com/OR13/draft-steele-transparency-service/blob/main/CONTRIBUTING.md).

Contributions can be made by creating pull requests.
The GitHub interface supports creating pull requests using the Edit (✏) button.


## Command Line Usage

Formatted text and HTML versions of the draft can be built using `make`.

```sh
$ make
```

Command line usage requires that you have the necessary software installed.  See
[the instructions](https://github.com/martinthomson/i-d-template/blob/main/doc/SETUP.md).

