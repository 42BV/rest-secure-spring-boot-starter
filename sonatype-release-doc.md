# Release to Maven Central

1. Create a [ticket with Sonatype](http://central.sonatype.org/pages/ossrh-guide.html)  
   (This has to be done by our maintenance department once per project).

2. Install a [gpg client](http://central.sonatype.org/pages/apache-maven.html#other-prerequisites) to sign the deployment artifacts  
   (This step has obviously to be done once per client).

3. Prepare the release:
   For java 17 reflection problems

```shell
export MAVEN_OPTS="--add-opens=java.base/java.util=ALL-UNNAMED --add-opens=java.base/java.lang.reflect=ALL-UNNAMED --add-opens=java.base/java.text=ALL-UNNAMED --add-opens=java.desktop/java.awt.font=ALL-UNNAMED"
```

  For gpg problems (inappropriate ioctl for device)

```shell
export GPG_TTY=$(tty)
```

Then, run this command to prepare the release.

`$ mvn release:prepare`

4. Perform the release:  
   `$ mvn release:perform`

5. Verify the release on Maven central:

- Navigate to [oss.sonatype.org](https://oss.sonatype.org/)
- Log in
- Go to 'Staging Repositories'
- Search on '42'
- Select the artifact
- Press 'close'
- Wait for closing to finish
- Press 'release'
