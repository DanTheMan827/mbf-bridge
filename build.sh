# https://github.com/walles/riff/blob/master/release.sh

rm -rf bin/mac

archs="x86_64 aarch64"
sdk_version="macosx12.3"
for arch in $archs; do
  target="$arch-apple-darwin"
  rustup target add $target
  SDKROOT=$(xcrun -sdk $sdk_version --show-sdk-path) \
    MACOSX_DEPLOYMENT_TARGET=$(xcrun -sdk $sdk_version --show-sdk-platform-version) \
      cargo build --target $target --release
  cp -r ModsBeforeFriday.app target/$target/release
  cp target/$target/release/mbf_bridge target/$target/release/ModsBeforeFriday.app/Contents/MacOS/mbf-bridge
  mkdir -p bin/mac/$arch
  rm -f bin/mac/$arch/mbf-bridge.zip
  pushd target/$target/release
  zip -r ../../../bin/mac/$arch/mbf-bridge.zip ModsBeforeFriday.app
  popd
done

mv bin/mac/x86_64 bin/mac/x86-64

arch="universal"
mkdir -p target/$arch/release
cp -r ModsBeforeFriday.app target/$arch/release
lipo -create \
  -output target/$arch/release/ModsBeforeFriday.app/Contents/MacOS/mbf-bridge \
  target/x86_64-apple-darwin/release/mbf_bridge \
  target/aarch64-apple-darwin/release/mbf_bridge
mkdir -p bin/mac/$arch
rm -f bin/mac/$arch/mbf-bridge.zip
pushd target/$arch/release
zip -r ../../../bin/mac/$arch/mbf-bridge.zip ModsBeforeFriday.app
popd
