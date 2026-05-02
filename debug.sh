docker run --rm -it \
  --mount type=volume,src=svelaxum-data,dst=/data \
  debian:bookworm-slim \
  bash