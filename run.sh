# !/bin/bash

# load from tarball
# docker load < svelaxum.tar.gz

# load from registry
#docker login ghcr.io -u youruser --password-stdin <<< $GITHUB_TOKEN
#docker pull ghcr.io/youruser/svelaxum:latest

docker rm -f svelaxum

docker run -d \
  --name svelaxum \
  --restart unless-stopped \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --tmpfs /tmp:size=32m,noexec,nosuid \
  --mount type=volume,src=svelaxum-data,dst=/data \
  -p 127.0.0.1:8080:3000 \
  svelaxum:release 
# ghcr.io/youruser/svelaxum:latest