# custom-codeql

This repository is intended to be a working directory for any custom CodeQL work until it finds a permanent home in OSS.  I provide no warranty on the works within.

## Structure 🚧

```
|-- .github ( Contains GitHub Actions and helpers)
|-- config ( Contains CodeQL configuration files for various purposes)
|-- java
    |-- debugging (Queries used for debugging Java CodeQL)

```


## Getting Started

### Config file usage

Use the configuration files from any configuration!
```yml
    - name: Initialize CodeQL
      uses: github/codeql-action/init@v3
      with:
        languages: ${{ matrix.language }}
        config-file: felickz/custom-codeql/config/codeql-synthetics.yml@main
```


### Packaging Ex

```
codeql pack install .\java\
codeql pack create .\java\

gh auth token | codeql pack publish .\java --github-auth-stdin
```

## Model Pack ex
```
#You shouldn't need to run pack install for a model pack, create just runs a subset of things that publish does (creates the pack, but doesn't bundle it or zip it)
codeql pack create .\java\extensions

echo "<pat>"  | codeql pack publish . --github-auth-stdin
```