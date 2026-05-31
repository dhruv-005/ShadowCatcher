// ============================================
// SHADOW CATCHER - Triage Benchmarks
// ============================================

use criterion::{
    black_box, criterion_group, criterion_main,
    Criterion, BenchmarkId, Throughput,
};
use shadow_core::triage::{
    MagicBytesDetector,
    ExtensionChecker,
    HeaderParser,
};
use shadow_core::triage::magic_bytes::FileType;

// ─────────────────────────────────────────
// TEST DATA
// ─────────────────────────────────────────

fn png_header() -> Vec<u8> {
    let mut h = b"\x89PNG\r\n\x1a\n".to_vec();
    h.extend_from_slice(&[0u8; 504]);
    h
}

fn pe_header() -> Vec<u8> {
    let mut h = b"MZ\x90\x00\x03\x00".to_vec();
    h.extend_from_slice(b"This program cannot be run in DOS mode\r\n");
    h.extend_from_slice(&[0u8; 466]);
    h
}

fn mp4_header() -> Vec<u8> {
    let mut h = vec![0u8, 0, 0, 0x18];
    h.extend_from_slice(b"ftypisom");
    h.extend_from_slice(&[0u8; 500]);
    h
}

fn random_bytes() -> Vec<u8> {
    (0..512).map(|i| (i * 37 % 256) as u8).collect()
}

// ─────────────────────────────────────────
// MAGIC BYTES BENCHMARKS
// ─────────────────────────────────────────

fn bench_magic_detection(c: &mut Criterion) {
    let detector = MagicBytesDetector::new();
    let headers = vec![
        ("png",     png_header()),
        ("pe",      pe_header()),
        ("mp4",     mp4_header()),
        ("unknown", random_bytes()),
    ];

    let mut group = c.benchmark_group("magic_detection");
    group.throughput(Throughput::Elements(1));

    for (name, header) in &headers {
        group.bench_with_input(
            BenchmarkId::new("detect", name),
            header,
            |b, h| {
                b.iter(|| {
                    black_box(detector.detect(black_box(h)))
                })
            },
        );
    }
    group.finish();
}

fn bench_magic_detection_batch(c: &mut Criterion) {
    let detector = MagicBytesDetector::new();
    let headers: Vec<Vec<u8>> = (0..100)
        .map(|i| {
            if i % 3 == 0 {
                png_header()
            } else if i % 3 == 1 {
                pe_header()
            } else {
                mp4_header()
            }
        })
        .collect();

    let mut group = c.benchmark_group("magic_batch");
    group.throughput(Throughput::Elements(100));

    group.bench_function("detect_100_files", |b| {
        b.iter(|| {
            for h in &headers {
                black_box(detector.detect(black_box(h)));
            }
        })
    });
    group.finish();
}

// ─────────────────────────────────────────
// EXTENSION CHECKER BENCHMARKS
// ─────────────────────────────────────────

fn bench_extension_checker(c: &mut Criterion) {
    let checker = ExtensionChecker::new();
    let test_cases = vec![
        ("png", FileType::Png),
        ("mp4", FileType::Mp4),
        ("exe", FileType::PeExecutable),
        ("jpg", FileType::Jpeg),
    ];

    let mut group = c.benchmark_group("extension_checker");
    group.throughput(Throughput::Elements(1));

    for (ext, file_type) in &test_cases {
        group.bench_with_input(
            BenchmarkId::new("is_spoofed", ext),
            ext,
            |b, e| {
                b.iter(|| {
                    black_box(checker.is_spoofed(
                        black_box(e),
                        black_box(file_type),
                    ))
                })
            },
        );
    }

    group.bench_function("get_risk_score", |b| {
        b.iter(|| {
            black_box(checker.get_risk_score(black_box("exe")))
        })
    });

    group.bench_function("validate_url", |b| {
        b.iter(|| {
            black_box(checker.validate_url(
                black_box("https://example.com/video.mp4?quality=high")
            ))
        })
    });

    group.finish();
}

// ─────────────────────────────────────────
// HEADER PARSER BENCHMARKS
// ─────────────────────────────────────────

fn bench_header_parser(c: &mut Criterion) {
    let parser = HeaderParser::new();
    let headers = vec![
        ("clean_png", png_header(), FileType::Png),
        ("pe_file",   pe_header(), FileType::PeExecutable),
    ];

    let mut group = c.benchmark_group("header_parser");
    group.throughput(Throughput::Bytes(512));

    for (name, header, file_type) in &headers {
        group.bench_with_input(
            BenchmarkId::new("analyze", name),
            header,
            |b, h| {
                b.iter(|| {
                    black_box(parser.analyze(
                        black_box(h),
                        black_box(file_type),
                    ))
                })
            },
        );
    }
    group.finish();
}

// ─────────────────────────────────────────
// COMBINED PIPELINE BENCHMARK
// ─────────────────────────────────────────

fn bench_full_triage_pipeline(c: &mut Criterion) {
    let detector = MagicBytesDetector::new();
    let checker = ExtensionChecker::new();
    let parser = HeaderParser::new();

    let test_files = vec![
        ("png_valid", png_header(), "image.png"),
        ("pe_spoofed", pe_header(), "image.png"),
        ("mp4_valid", mp4_header(), "video.mp4"),
    ];

    let mut group = c.benchmark_group("full_pipeline");
    group.throughput(Throughput::Bytes(512));

    for (name, header, filename) in &test_files {
        group.bench_with_input(
            BenchmarkId::new("scan", name),
            header,
            |b, h| {
                b.iter(|| {
                    let detected = detector.detect(black_box(h));
                    let ext = ExtensionChecker::get_extension(
                        black_box(filename)
                    );
                    let _spoofed = checker.is_spoofed(&ext, &detected);
                    let _issues = parser.analyze(h, &detected);
                })
            },
        );
    }
    group.finish();
}

// ─────────────────────────────────────────
// CRITERION GROUPS
// ─────────────────────────────────────────

criterion_group!(
    benches,
    bench_magic_detection,
    bench_magic_detection_batch,
    bench_extension_checker,
    bench_header_parser,
    bench_full_triage_pipeline,
);
criterion_main!(benches);
