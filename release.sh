docker build -f .devcontainer/Dockerfile -t svelaxum-dev .
docker build -f Dockerfile.prod -t svelaxum:release .

# release with tarball
#docker save svelaxum:release | gzip > svelaxum.tar.gz
#scp svelaxum.tar.gz user@your-vm-ip:~

# release with github registry
#docker build -f Dockerfile.prod -t ghcr.io/youruser/svelaxum:latest .

# Login and push
#echo $GITHUB_TOKEN | docker login ghcr.io -u youruser --password-stdin
#docker push ghcr.io/youruser/svelaxum:latest
