# Configuration Files

This directory contains various custom configuration files for CodeQL analysis. 

## Usage


### GitHub Actions
```yml
    # Initializes the CodeQL tools for scanning using the custom configuration designed to provide maximum number of alerts for synthetic applications (reduced false negatives at the impact of more false positives).
    - name: Initialize CodeQL
      uses: github/codeql-action/init@v3
      with:
        languages: ${{ matrix.language }}
        config-file: felickz/custom-codeql/config/codeql-synthetics.yml@main
```

### Azure DevOps
```yml    
    - pwsh: |
        Invoke-WebRequest -Uri "https://raw.githubusercontent.com/felickz/custom-codeql/main/config/codeql-synthetics.yml" -OutFile "$(Agent.TempDirectory)/codeql-synthetics.yml"
    displayName: Copy down CodeQL Config for synthetic applications

    # Initializes the CodeQL tools for scanning using the custom configuration designed to provide maximum number of alerts for synthetic applications (reduced false negatives at the impact of more false positives).
    - task: AdvancedSecurity-Codeql-Init@1
    inputs:
        languages: 'csharp'
        configfilepath: '$(Agent.TempDirectory)/codeql-synthetics.yml'

```

## Inventory

## [codeql-audit.yml](codeql-audit.yml)

This configuration is used for auditing the codebase. These queries will normally be executed using partial path queries - not looking for full source/sink flows. Use these very broad queries or even [partial flow paths](https://codeql.github.com/docs/writing-codeql-queries/debugging-data-flow-queries-using-partial-flow/) to help deduce where the taint might be breaking and to discover areas for potential customization enhancement.

## [codeql-security-extended-no-telemetry.yml](codeql-security-extended-no-telemetry.yml)

A reference configuration that is a variant of the security-extended query suite that also disables telemetry. A common use case is when a telemetry query is failing the analysis run.  

## [codeql-super-extended.yml](codeql-super-extended.yml)

This configuration uses all possible queries from the CodeQL built in packs to create a super-extended security analysis configuration  (aka yolo config). It includes more queries than the standard security-experimental suite, providing a more thorough analysis at the cost of longer analysis times and potential false positives.  It includes:
- queries marked as `@precision: low` or missing a precision
- queries marked as `@problem.severity: recommendation`
- queries in `\experimental\` folders

## [codeql-synthetics.yml](codeql-synthetics.yml)

This file is used for analyzing synthetic code samples. This configuration uses all possible queries from the CodeQL built in packs (same as [codeql-super-extended.yml](codeql-super-extended.yml) config ) along with additional OSS queries and data extensions. It includes more queries than the standard security-experimental suite, providing a more thorough analysis at the cost of longer analysis times and potential false positives.  It includes:
- queries marked as `@precision: low` or missing a precision
- queries marked as `@problem.severity: recommendation`
- queries in `\experimental\` folders

## [codeql-local.yml](codeql-local.yml)
Use this configuration file when looking to expand the sources of vulnerability data using CodeQL Built in queries,custom queries, and data extensions.
A notable amount of false positives may be found in this configuration.  It includes:
- built in queries
- `threat-models: local`
- Suites that include community queries/suites/data extensions that are explicitly looking for local sources:
  - githubsecuritylab/codeql-java-queries:suites/java-local.qls
  - githubsecuritylab/codeql-python-queries:suites/python-local.qls