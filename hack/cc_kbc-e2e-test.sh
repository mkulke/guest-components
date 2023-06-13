#!/bin/bash

set -euo pipefail

KBS_SOCKET=127.0.0.1:8080
KEYPROVIDER_SOCKET=127.0.0.1:50000
KBS_RESOURCE=default/key/image

cleanup() {
  if [ -z "${BUILD_DIR:-}" ]; then
	rm -rf "$build_dir"
  fi
  docker rm -f registry
  jobs -p | xargs kill
}

trap 'cleanup' EXIT

build_dir="${BUILD_DIR:-$(mktemp -d)}"
pushd "$build_dir"

[ -d "./image-rs" ] || git clone https://github.com/confidential-containers/image-rs.git
[ -d "./attestation-agent" ] || git clone https://github.com/confidential-containers/attestation-agent.git
[ -d "./kbs" ] || git clone https://github.com/confidential-containers/kbs.git

echo "Build coco_keyprovider..."
pushd attestation-agent
cargo b --release -p coco_keyprovider

echo "Start coco_keyprovider..."
./target/release/coco_keyprovider --socket "$KEYPROVIDER_SOCKET" &
keyprovider_pid=$!
sleep 1
if ! kill -0 "$keyprovider_pid"; then
  echo "coco_keyprovider failed to start"
  exit 1
fi

popd

echo "Start local docker registry..."
docker run -d -p 5000:5000 --restart=always --name registry registry:2

echo "Encrypt image with random secret..."
cat <<EOF > ocicrypt.conf
{
  "key-providers": {
	"attestation-agent": {
	  "grpc": "$KEYPROVIDER_SOCKET"
	}
  }
}
EOF
keypath="${PWD}/image_key"
head -c 32 < /dev/urandom > "$keypath"
keyid="kbs://${KBS_SOCKET}/${KBS_RESOURCE}"
OCICRYPT_KEYPROVIDER_CONFIG="${PWD}/ocicrypt.conf" skopeo copy \
  --insecure-policy \
  --encryption-key "provider:attestation-agent:keypath=${keypath}::keyid=${keyid}::algorithm=A256GCM" \
  --dest-tls-verify=false \
  docker://busybox \
  docker://localhost:5000/coco/busybox_encrypted:v1
# Stop coco_keyprovider service
kill "$keyprovider_pid"

echo "Build kbs..."
pushd kbs
cargo b --release -p kbs 

echo "Start kbs..."
openssl genpkey -algorithm ed25519 > kbs.key
openssl pkey -in kbs.key -pubout -out kbs.pem
mkdir -p "/opt/confidential-containers/kbs/repository/$(dirname "$KBS_RESOURCE")"
cp "$keypath" "/opt/confidential-containers/kbs/repository/${KBS_RESOURCE}"
./target/release/kbs --socket "$KBS_SOCKET" --insecure-http --auth-public-key ./kbs.pem &
kbs_pid=$!
sleep 1
if ! kill -0 "$kbs_pid"; then
  echo "kbs failed to start"
  exit 1
fi
popd

echo "Build attestation-agent..."
pushd attestation-agent
cargo b --release -p attestation-agent \
  --no-default-features \
  --features grpc,cc_kbc,openssl

echo "Start attestation-agent..."
AA_SAMPLE_ATTESTER_TEST=1 ./target/release/attestation-agent \
  --keyprovider_sock "$KEYPROVIDER_SOCKET" --getresource_sock 127.0.0.1:50001 &
aa_pid=$!
sleep 1
if ! kill -0 "$aa_pid"; then
  echo "attestation-agent failed to start"
  exit 1
fi
popd

echo "Build image-rs..."
pushd image-rs
cargo b --features encryption-ring,getresource,insecure-registry

echo "Run image decryption test..."
CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER='sudo -E' cargo test \
  --features encryption-ring,getresource,insecure-registry \
  -- --include-ignored --test decrypt_layers_via_kbs --nocapture
kill "$kbs_pid" "$aa_pid"
