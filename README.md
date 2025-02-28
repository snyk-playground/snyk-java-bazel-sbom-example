Snyk Java Bazel SBOM Example
----------------------------

This project demonstrates the usage of Bazel to retrieve dependencies from Maven
repositories, build a program, create a CycloneDX SBOM, and test the SBOM with Snyk.

To build this example, you will need to [install
Bazel](http://bazel.io/docs/install.html).

The Java application makes use of a library in
[Guava](https://github.com/google/guava), which is downloaded from a remote
repository using Maven.

This application demonstrates the usage of
[`rules_jvm_external`](https://github.com/bazelbuild/rules_jvm_external/) to
configure dependencies. The dependencies are configured in the `WORKSPACE` file.

Requirements:

- Python 3.10.14
- Bazel 7.1.0
- [Snyk Token](https://docs.snyk.io/snyk-cli/authenticate-to-use-the-cli#steps-to-authenticate-using-a-known-snyk-api-token)

Build the application by running:

```
$ bazel build :java-maven
```

Create Bazel dependencies XML file:

```
$ bazel query "deps(//app/package:target)" --noimplicit_deps --output xml > bazel_deps.xml
```

Create a CycloneDX SBOM:

```
$ python3 index.py generate-sbom --input bazel_deps.xml --output sbom.json --version v1.6
```

Test the SBOM with Snyk:

```
$ python3 index.py test-sbom --input sbom.json --org-id <your-snyk-org-id>
```