// ============================================
// SHADOW CATCHER - Build Script
// Runs before compilation to set up
// native dependencies and FFI bindings
// ============================================

use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/");
    println!("cargo:rerun-if-changed=../frontend/assets/ai/shadow_brain.onnx");

    let target_os = env::var("CARGO_CFG_TARGET_OS")
        .unwrap_or_default();
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH")
        .unwrap_or_default();
    let out_dir = PathBuf::from(
        env::var("OUT_DIR").unwrap()
    );
    let manifest_dir = PathBuf::from(
        env::var("CARGO_MANIFEST_DIR").unwrap()
    );

    println!(
        "cargo:warning=Building for {}/{}",
        target_os, target_arch
    );

    // ── Platform-specific setup ──
    match target_os.as_str() {
        "android" => setup_android(&target_arch),
        "windows" => setup_windows(),
        "linux"   => setup_linux(),
        "macos"   => setup_macos(),
        _         => {}
    }

    // ── ONNX Runtime setup ──
    setup_onnx_runtime(&manifest_dir, &out_dir, &target_os);

    // ── FFmpeg setup ──
    setup_ffmpeg(&target_os);

    // ── Generate FFI bindings ──
    generate_ffi_bindings(&out_dir);

    // ── Emit build metadata ──
    emit_build_metadata();
}

// ─────────────────────────────────────────
// PLATFORM SETUP
// ─────────────────────────────────────────

fn setup_android(arch: &str) {
    println!("cargo:warning=Setting up Android build for {}", arch);

    // Android NDK library paths
    if let Ok(ndk_home) = env::var("ANDROID_NDK_HOME") {
        let lib_path = match arch {
            "aarch64" => format!(
                "{}/toolchains/llvm/prebuilt/linux-x86_64/\
                 sysroot/usr/lib/aarch64-linux-android",
                ndk_home
            ),
            "arm" => format!(
                "{}/toolchains/llvm/prebuilt/linux-x86_64/\
                 sysroot/usr/lib/arm-linux-androideabi",
                ndk_home
            ),
            "x86_64" => format!(
                "{}/toolchains/llvm/prebuilt/linux-x86_64/\
                 sysroot/usr/lib/x86_64-linux-android",
                ndk_home
            ),
            _ => return,
        };
        println!("cargo:rustc-link-search=native={}", lib_path);
    }

    println!("cargo:rustc-link-lib=android");
    println!("cargo:rustc-link-lib=log");
    println!("cargo:rustc-link-lib=OpenSLES");
}

fn setup_windows() {
    println!("cargo:warning=Setting up Windows build");
    println!("cargo:rustc-link-lib=dylib=user32");
    println!("cargo:rustc-link-lib=dylib=shell32");
    println!("cargo:rustc-link-lib=dylib=ole32");
    println!("cargo:rustc-link-lib=dylib=advapi32");
    println!("cargo:rustc-link-lib=dylib=ws2_32");
    println!("cargo:rustc-link-lib=dylib=bcrypt");
}

fn setup_linux() {
    println!("cargo:warning=Setting up Linux build");
    println!("cargo:rustc-link-lib=dylib=pthread");
    println!("cargo:rustc-link-lib=dylib=dl");
    println!("cargo:rustc-link-lib=dylib=m");

    // pkg-config for GTK (used by Flutter Linux)
    if let Ok(output) = std::process::Command::new("pkg-config")
        .args(["--libs", "gtk+-3.0"])
        .output()
    {
        if output.status.success() {
            println!("cargo:warning=GTK3 found via pkg-config");
        }
    }
}

fn setup_macos() {
    println!("cargo:warning=Setting up macOS build");
    println!("cargo:rustc-link-lib=framework=Foundation");
    println!("cargo:rustc-link-lib=framework=Security");
    println!("cargo:rustc-link-lib=framework=CoreFoundation");
}

// ─────────────────────────────────────────
// ONNX RUNTIME SETUP
// ─────────────────────────────────────────

fn setup_onnx_runtime(
    manifest_dir: &PathBuf,
    out_dir: &PathBuf,
    target_os: &str,
) {
    println!("cargo:warning=Setting up ONNX Runtime");

    // Check for ORT_LIB_LOCATION override
    if let Ok(ort_lib) = env::var("ORT_LIB_LOCATION") {
        println!("cargo:rustc-link-search=native={}", ort_lib);
        println!("cargo:warning=Using ORT from: {}", ort_lib);
        return;
    }

    // Default ORT library path
    let ort_lib_name = match target_os {
        "windows" => "onnxruntime.dll",
        "macos"   => "libonnxruntime.dylib",
        _         => "libonnxruntime.so",
    };

    let ort_dir = manifest_dir
        .parent()
        .unwrap_or(manifest_dir)
        .join("libs")
        .join("onnxruntime");

    if ort_dir.exists() {
        println!(
            "cargo:rustc-link-search=native={}",
            ort_dir.display()
        );
        println!("cargo:warning=ONNX Runtime dir: {}", ort_dir.display());
    } else {
        println!(
            "cargo:warning=ORT dir not found: {}. \
             Will use system ORT or ort crate bundled version.",
            ort_dir.display()
        );
    }

    // Copy ONNX model to output for testing
    let model_src = manifest_dir
        .parent()
        .unwrap_or(manifest_dir)
        .join("frontend")
        .join("assets")
        .join("ai")
        .join("shadow_brain.onnx");

    let model_dst = out_dir.join("shadow_brain.onnx");

    if model_src.exists() {
        std::fs::copy(&model_src, &model_dst).ok();
        println!(
            "cargo:warning=Copied ONNX model to: {}",
            model_dst.display()
        );
    }
}

// ─────────────────────────────────────────
// FFMPEG SETUP
// ─────────────────────────────────────────

fn setup_ffmpeg(target_os: &str) {
    println!("cargo:warning=Setting up FFmpeg");

    if let Ok(ffmpeg_dir) = env::var("FFMPEG_DIR") {
        println!(
            "cargo:rustc-link-search=native={}/lib",
            ffmpeg_dir
        );
    }

    // Link FFmpeg libraries
    let ffmpeg_libs = [
        "avcodec",
        "avformat",
        "avutil",
        "swscale",
        "swresample",
        "avfilter",
    ];

    for lib in &ffmpeg_libs {
        println!("cargo:rustc-link-lib=dylib={}", lib);
    }

    match target_os {
        "windows" => {
            println!("cargo:rustc-link-lib=dylib=avdevice");
        }
        "linux" => {
            println!("cargo:rustc-link-lib=dylib=avdevice");
            println!("cargo:rustc-link-lib=dylib=va");
            println!("cargo:rustc-link-lib=dylib=va-drm");
        }
        _ => {}
    }
}

// ─────────────────────────────────────────
// FFI BINDINGS
// ─────────────────────────────────────────

fn generate_ffi_bindings(out_dir: &PathBuf) {
    println!("cargo:warning=Generating FFI bindings");

    // flutter_rust_bridge generates bindings automatically
    // This is a placeholder for any custom cbindgen usage

    let bindings_path = out_dir.join("bindings.rs");
    let bindings_content = r#"
// Auto-generated FFI bindings
// Do not edit manually
pub const SHADOW_CORE_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const SHADOW_CORE_NAME: &str = env!("CARGO_PKG_NAME");
"#;

    std::fs::write(&bindings_path, bindings_content).ok();
}

// ─────────────────────────────────────────
// BUILD METADATA
// ─────────────────────────────────────────

fn emit_build_metadata() {
    // Embed build timestamp
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    println!(
        "cargo:rustc-env=SHADOW_BUILD_TIMESTAMP={}",
        timestamp
    );

    // Embed git hash if available
    let git_hash = std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .unwrap_or_else(|| "unknown".to_string());

    println!(
        "cargo:rustc-env=SHADOW_GIT_HASH={}",
        git_hash.trim()
    );

    println!(
        "cargo:warning=Build metadata: \
         timestamp={}, git={}",
        timestamp,
        git_hash.trim()
    );
}
