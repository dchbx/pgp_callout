# pgp_callout

This is a callout jar for the Oracle B2B gateway.  It allows usage of PGP encoding on the in/out channels of the gateway.

## Building

In order to build the jar, you will need to perform 2 steps: install the dependency in your local maven repository, and build the jar artifact using maven.

The dependency can be installed by changing directory to the deps subdirectory and running the following maven command:
```
mvn install:install-file -Dfile=b2b.jar -DgroupId=com.oracle.b2b -DartifactId=b2b -Dpackaging=jar -Dversion=11.1.1
```

You can then build the jar as an assembly artifact:
```
mvn compile assembly:single
```

## Packaging Notes

Be aware that the artifact is built as a shaded jar with the PGP libraries included inside.
