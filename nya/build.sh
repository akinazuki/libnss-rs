cd ${SOURCE_DIR}
echo "Building for architecture: ${TARGET}"
echo "Target dir: ${CARGO_TARGET_DIR}"
GLIBC_VER=`ldd --version | grep ldd | awk '{print $NF}'`
echo "GLIBC_VERSION: ${GLIBC_VER}"
echo "Starting build..."
cargo build --release --target=${TARGET} --verbose
echo "[✅] Builder finished with exit code: $?"
echo "> md5sum `md5sum ${CARGO_TARGET_DIR}/${TARGET}/release/libnss_${OUTPUT_NAME}.so`"
echo "> libnss_${OUTPUT_NAME}.so build date: `date -r ${CARGO_TARGET_DIR}/${TARGET}/release/libnss_${OUTPUT_NAME}.so`"
echo "> ldd ${CARGO_TARGET_DIR}/${TARGET}/release/libnss_${OUTPUT_NAME}.so"
ldd ${CARGO_TARGET_DIR}/${TARGET}/release/libnss_${OUTPUT_NAME}.so